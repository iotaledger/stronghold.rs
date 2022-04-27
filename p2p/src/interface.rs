// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod event_channel;
mod event_loop;

pub use event_channel::{ChannelSinkConfig, EventChannel};
use event_loop::{EventLoop, SwarmCommand};
use smallvec::SmallVec;

use crate::{
    behaviour::{BehaviourEvent, ConfigConfig, InboundFailure, NetworkBehaviour, OutboundFailure, Request, RequestId},
    firewall::{FirewallRequest, FirewallRules, FwRequest, Rule},
    AddressInfo, RelayNotSupported,
};

use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
    AsyncRead, AsyncWrite, FutureExt,
};
use libp2p::{
    core::{transport::Transport, upgrade, ConnectedPoint, Executor, Multiaddr, PeerId},
    identity::Keypair,
    mdns::{Mdns, MdnsConfig},
    multihash::Multihash,
    noise::{AuthenticKeypair, Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    relay::v1::{new_transport_and_behaviour, RelayConfig},
    swarm::{
        ConnectionError, ConnectionLimit, ConnectionLimits as Libp2pConnectionLimits, DialError,
        PendingConnectionError, SwarmBuilder, SwarmEvent,
    },
    yamux::YamuxConfig,
    TransportError,
};
#[cfg(feature = "tcp-transport")]
use libp2p::{dns::TokioDnsConfig, tcp::TokioTcpConfig, websocket::WsConfig};
use serde::{Deserialize, Serialize};
use std::{io, num::NonZeroU32, time::Duration};
use thiserror::Error;

/// Central interface for listening to the network, establishing connection to remote peers, sending requests `Rq`
/// and receiving their response `Rs`.
///
/// All [`Swarm`][`libp2p::Swarm`] interaction takes place in an event-loop in a separate task.
/// [`StrongholdP2p`] is essentially a wrapper for the Sender side of a mpsc channel, which is used to initiate
/// operations on the swarm. Thus it is safe to clone, while still operating on the same swarm.
///
/// Refer to [`StrongholdP2pBuilder`] for more information on the default configuration.
///
/// ## Firewall configuration
///
/// The firewall allows the user to set default-, and peer-specific firewall rules which are used
/// to approve every inbound request.
/// The firewall operates on the `TRq` type, which can be a modified version of the "real" request, that only includes
/// the firewall-relevant information. Apart from static rules, the firewall-channel may be used for asynchronous rules:
/// 1. If no firewall rule is set for a peer and a request occurs, a [`FirewallRequest::PeerSpecificRule`]
///    is sent through the channel. The responded rule is then set as firewall rule  for this peer.
///    If the user does not response in time or the receiving side of the channel was dropped, the request is rejected.
/// 2. If [`Rule::Ask`] has been set, a [`FirewallRequest::RequestApproval`] is sent on each request for
///    individual approval. If the user does not response in time or the receiving side of the channel was dropped, the
/// request is rejected.
///
/// ## Example
///
/// ```
/// # use serde::{Serialize, Deserialize};
/// # use p2p::{firewall::{FirewallRules, FwRequest}, ChannelSinkConfig, EventChannel, StrongholdP2p};
/// # use futures::channel::mpsc;
/// #
/// // Type of the requests send to the remote.
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// enum Request {
///     Ping,
///     Message(String),
/// }
///
/// // Trimmed version of the request that is used for validation in the firewall.
/// // In case of a `FirewallRequest::RequestApproval`, this is the message that is bubbled up through the
/// // firewall channel.
/// //
/// // This type is optional but may be needed because e.g. no details the actual request should be exposed to the receiving side of the firewall-channel.
/// #[derive(Debug, Clone)]
/// enum RequestType {
///     Ping,
///     Message,
/// }
///
/// impl FwRequest<Request> for RequestType {
///     fn from_request(request: &Request) -> RequestType {
///         match request {
///             Request::Ping => RequestType::Ping,
///             Request::Message(..) => RequestType::Message,
///         }
///     }
/// }
///
/// // Type of the response send back.
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// enum Response {
///     Pong,
///     Message(String),
/// }
///
/// // Channel used for asynchronous firewall rules.
/// let (firewall_tx, firewall_rx) = mpsc::channel(10);
///
/// // Channel through which inbound requests are forwarded.
/// let (request_tx, request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
///
/// // Optional channel through which current events in the network are sent, e.g.
/// // peers connecting / disconnecting, listener events or non-fatal failures.
/// let (events_tx, events_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
///
/// let p2p = StrongholdP2p::<Request, Response, RequestType>::new(
///     firewall_tx,
///     request_tx,
///     Some(events_tx),
///     FirewallRules::allow_all(),
/// );
/// ```
#[derive(Clone)]
pub struct StrongholdP2p<Rq, Rs, TRq = Rq>
where
    // Request message type
    Rq: Request,
    // Response message type
    Rs: Request,
    // Optional, tailored request-type that is used in the firewall to get approval.
    // This has the purpose of trimming the actual request down to the firewall-relevant information and e.g. avoid
    // exposing the request's actual content.
    TRq: FwRequest<Rq>,
{
    // Id of the local peer.
    local_peer_id: PeerId,
    // Channel for sending `SwarmCommand` to the `EventLoop`.
    // The `SwarmCommand`s trigger according operations on the Swarm.
    // The result of an operation is received via the oneshot Receiver that is included in each type.
    command_tx: mpsc::Sender<SwarmCommand<Rq, Rs, TRq>>,
}

impl<Rq, Rs, TRq> StrongholdP2p<Rq, Rs, TRq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    /// Create a new [`StrongholdP2p`] instance with the default configuration.
    /// Refer to [`StrongholdP2pBuilder::new`] and [`StrongholdP2pBuilder::build`] for more information.
    #[cfg(feature = "tcp-transport")]
    pub async fn new(
        firewall_channel: mpsc::Sender<FirewallRequest<TRq>>,
        requests_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
        events_channel: Option<EventChannel<NetworkEvent>>,
        firewall_rules: FirewallRules<TRq>,
    ) -> Result<Self, io::Error> {
        StrongholdP2pBuilder::new(firewall_channel, requests_channel, events_channel, firewall_rules)
            .build()
            .await
    }

    /// Get the [`PeerId`] of the local peer.
    pub fn peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Send a new request to a remote peer.
    ///
    /// This will attempt to establish a connection to the remote via one of the known addresses if there is no active
    /// connection.
    pub async fn send_request(&mut self, peer: PeerId, request: Rq) -> Result<Rs, OutboundFailure> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::SendRequest {
            peer,
            request,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Start listening on the network on the given address.
    /// In case of a tcp-transport, the address `/ip4/0.0.0.0/tcp/0` can be set if an OS-assigned address should be
    /// used.
    ///
    /// **Note**: Depending on the used transport, this may produce multiple listening addresses.
    /// This method only returns the first reported listening address for the new listener.
    /// All active listening addresses for each listener can be obtained from [`StrongholdP2p::listeners`]
    pub async fn start_listening(&mut self, address: Multiaddr) -> Result<Multiaddr, ListenErr> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::StartListening { address, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Start listening via a relay peer. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    /// The returned address will follow the scheme `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`.
    pub async fn start_relayed_listening(
        &mut self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ListenRelayErr> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::StartRelayedListening {
            relay,
            relay_addr,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    //// Currently active listeners.
    pub async fn listeners(&mut self) -> Vec<Listener> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::GetListeners { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening on all listeners.
    pub async fn stop_listening(&mut self) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::StopListening { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening on the listener associated with the given address.
    pub async fn stop_listening_addr(&mut self, address: Multiaddr) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::StopListeningAddr { address, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening via the given relay.
    pub async fn stop_listening_relay(&mut self, relay: PeerId) -> bool {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::StopListeningRelay { relay, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Establish a new new connection to the remote peer.
    /// This will try each known address until either a connection was successful, or all failed.
    pub async fn connect_peer(&mut self, peer: PeerId) -> Result<Multiaddr, DialErr> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::ConnectPeer { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Set the default configuration for the firewall.
    ///
    /// If the rule is `None` a [`FirewallRequest::PeerSpecificRule`]
    /// request will be sent through the firewall channel when peers without a rule are sending a request.
    pub async fn set_firewall_default(&mut self, default: Option<Rule<TRq>>) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::SetFirewallDefault { default, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get the current firewall configuration.
    pub async fn get_firewall_config(&mut self) -> FirewallRules<TRq> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::GetFirewallConfig { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a default firewall rule.
    /// If there is no default rule and no peer-specific rule, a [`FirewallRequest::PeerSpecificRule`]
    /// request will be sent through the firewall channel
    pub async fn remove_firewall_default(&mut self) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::RemoveFirewallDefault { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub async fn set_peer_rule(&mut self, peer: PeerId, rule: Rule<TRq>) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::SetPeerRule { peer, rule, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a peer specific rule, which will result in using the firewall default rules.
    pub async fn remove_peer_rule(&mut self, peer: PeerId) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::RemovePeerRule { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get the known addresses for a remote peer.
    pub async fn get_addrs(&mut self, peer: PeerId) -> Vec<Multiaddr> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::GetPeerAddrs { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Add an address for the remote peer.
    pub async fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::AddPeerAddr {
            peer,
            address,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove an address from the known addresses of a remote peer.
    pub async fn remove_address(&mut self, peer: PeerId, address: Multiaddr) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::RemovePeerAddr {
            peer,
            address,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Export address info of remote peers and relays.
    pub async fn export_address_info(&mut self) -> AddressInfo {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::ExportAddressInfo { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(
        &mut self,
        peer: PeerId,
        address: Option<Multiaddr>,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::AddDialingRelay {
            peer,
            address,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a relay from the list of dialing relays.
    /// Returns `false` if the peer was not among the known relays.
    ///
    /// **Note**: Known relayed addresses for remote peers using this relay will not be influenced by this.
    pub async fn remove_dialing_relay(&mut self, peer: PeerId) -> bool {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::RemoveDialingRelay { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Configure whether it should be attempted to reach the remote via known relays, if it can not be reached via
    /// known addresses.
    pub async fn set_relay_fallback(
        &mut self,
        peer: PeerId,
        use_relay_fallback: bool,
    ) -> Result<(), RelayNotSupported> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::SetRelayFallback {
            peer,
            use_relay_fallback,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Dial the target via the specified relay.
    /// The `is_exclusive` parameter specifies whether other known relays should be used if using the set relay is not
    /// successful.
    ///
    /// Returns the relayed address of the local peer (`<relay-addr>/<relay-id>/p2p-circuit/<local-id>),
    /// if an address for the relay is known.
    pub async fn use_specific_relay(
        &mut self,
        target: PeerId,
        relay: PeerId,
        is_exclusive: bool,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::UseSpecificRelay {
            target,
            relay,
            is_exclusive,
            return_tx,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Bans a peer by its peer ID.
    ///
    /// Any incoming connection and any dialing attempt will immediately be rejected.
    /// This function has no effect if the peer is already banned.
    pub async fn ban_peer(&mut self, peer: PeerId) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::BanPeer { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Unbans a peer.
    pub async fn unban_peer(&mut self, peer: PeerId) {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::UnbanPeer { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Check whether the Network has an established connection to a peer.
    pub async fn is_connected(&mut self, peer: PeerId) -> bool {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::GetIsConnected { peer, return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get currently established connections.
    pub async fn established_connections(&mut self) -> Vec<(PeerId, Vec<ConnectedPoint>)> {
        let (return_tx, rx_yield) = oneshot::channel();
        let command = SwarmCommand::GetConnections { return_tx };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }
    async fn send_command(&mut self, command: SwarmCommand<Rq, Rs, TRq>) {
        let _ = poll_fn(|cx| self.command_tx.poll_ready(cx)).await;
        let _ = self.command_tx.start_send(command);
    }
}

/// Use existing keypair for authentication on the transport layer.
///
/// The local [`PeerId`] is derived from public key of the IdKeys.
pub enum InitKeypair {
    /// Identity Keys that are used to derive the noise keypair and peer id.
    IdKeys(Keypair),
    /// Use authenticated noise-keypair.
    ///
    /// **Note**:
    /// The `peer_id` has to be derived from the same keypair that is used to create the noise-keypair.
    /// Remote Peers will always observe us from the derived [`PeerId`], even if we set a different one
    /// here.
    Authenticated {
        peer_id: PeerId,
        noise_keypair: AuthenticKeypair<X25519Spec>,
    },
}

/// Builder for new `StrongholdP2p`.
///
/// Default behaviour:
/// - A new keypair is created and used, from which the [`PeerId`] of the local peer is derived.
/// - Max 5 connections to the same peer (per protocol only 1 is needed).
/// - Request-timeout, connection-timeout and firewall-timeout are 10s.
/// - [`Mdns`][`libp2p::mdns`] protocol is enabled. **Note**: This also broadcasts our own address and id to the local
///   network.
/// - [`Relay`][`libp2p::relay`] protocol is supported. *Note:* This also means that other peers can use our peer as
///   relay.
///
/// `StrongholdP2p` is build either via [`StrongholdP2pBuilder::build`] (requires feature **tcp-transport**) with a
/// pre-configured transport, or [`StrongholdP2pBuilder::build_with_transport`] with a custom transport.
///
/// When building a new `StrongholdP2p` a new [`Swarm`][libp2p::Swarm] is created and continuously polled for events.
/// Inbound requests are forwarded through a `mpsc::channel<ReceiveRequest<Rq, Rs>>`    .
/// Optionally all events regarding connections and listeners are forwarded as [`NetworkEvent`].
pub struct StrongholdP2pBuilder<Rq, Rs, TRq = Rq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    firewall_channel: mpsc::Sender<FirewallRequest<TRq>>,
    requests_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
    events_channel: Option<EventChannel<NetworkEvent>>,

    // Use an existing keypair instead of creating a new one.
    ident: Option<(AuthenticKeypair<X25519Spec>, PeerId)>,

    // Configuration of the underlying `NetworkBehaviour`.
    behaviour_config: ConfigConfig,

    // Limit of simultaneous connections.
    connections_limit: Option<ConnectionLimits>,

    // List of known addresses that were persisted from a former running instance.
    address_info: Option<AddressInfo>,

    // Firewall rules.
    firewall_rules: FirewallRules<TRq>,

    // Use Mdns protocol for peer discovery in the local network.
    //
    // Note: This also broadcasts our own address and id to the local network.
    support_mdns: bool,

    support_relay: bool,
}

impl<Rq, Rs, TRq> StrongholdP2pBuilder<Rq, Rs, TRq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    /// Parameters:
    /// - `firewall_channel`: Channel for [`FirewallRequest`] if there are no fixed rules in the firewall or
    ///   [`Rule::Ask`] was set.
    /// - `requests_channel`: Channel for forwarding inbound requests from remote peers
    /// - `events_channel`: Optional channel for forwarding all events in the swarm.
    pub fn new(
        firewall_channel: mpsc::Sender<FirewallRequest<TRq>>,
        requests_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
        events_channel: Option<EventChannel<NetworkEvent>>,
        firewall_rules: FirewallRules<TRq>,
    ) -> Self {
        StrongholdP2pBuilder {
            firewall_channel,
            requests_channel,
            events_channel,
            ident: None,
            behaviour_config: Default::default(),
            connections_limit: None,
            firewall_rules,
            support_mdns: true,
            support_relay: true,
            address_info: None,
        }
    }

    /// Set the keypair that is used for authenticating the communication on the transport layer.
    /// The local [`PeerId`] is derived from the keypair.
    pub fn with_keys(mut self, keys: InitKeypair) -> Self {
        let (keypair, id) = match keys {
            InitKeypair::IdKeys(keypair) => {
                let noise_keypair = NoiseKeypair::<X25519Spec>::new().into_authentic(&keypair).unwrap();
                let id = keypair.public().to_peer_id();
                (noise_keypair, id)
            }
            InitKeypair::Authenticated { peer_id, noise_keypair } => (noise_keypair, peer_id),
        };
        self.ident = Some((keypair, id));
        self
    }

    /// Set the limit for simultaneous connections.
    /// By default no connection limits apply.
    pub fn with_connections_limit(mut self, limit: ConnectionLimits) -> Self {
        self.connections_limit = Some(limit);
        self
    }

    /// Set a timeout for receiving a response after a request was sent.
    ///
    /// This applies for inbound and outbound requests.
    pub fn with_request_timeout(mut self, t: Duration) -> Self {
        self.behaviour_config.request_timeout = t;
        self
    }

    /// Set the timeout for a idle connection to a remote peer.
    pub fn with_connection_timeout(mut self, t: Duration) -> Self {
        self.behaviour_config.connection_timeout = t;
        self
    }

    /// Set timeout for [`FirewallRequest`]s send through the firewall-channel.
    ///
    /// See [`StrongholdP2p`] docs for more info.
    pub fn with_firewall_timeout(mut self, t: Duration) -> Self {
        self.behaviour_config.connection_timeout = t;
        self
    }

    /// Load the behaviour state from a former running instance.
    /// The state contains default and peer-specific rules, and the list of known addresses for remote peers.
    pub fn load_addresses(mut self, address_info: AddressInfo) -> Self {
        self.address_info = Some(address_info);
        self
    }

    /// Whether the peer should support the [`Mdns`][libp2p::mdns] protocol for peer discovery in a local network.
    ///
    /// **Note**: Enabling Mdns broadcasts our own address and id to the local network.
    pub fn with_mdns_support(mut self, support_mdns_protocol: bool) -> Self {
        self.support_mdns = support_mdns_protocol;
        self
    }

    /// Whether the peer should support the [`Relay`][libp2p::relay] protocol that allows dialing and listening via a
    /// relay peer.
    ///
    /// **Note:** enabling this protocol also means that other peers can use our peer as relay.
    pub fn with_relay_support(mut self, support_relay_protocol: bool) -> Self {
        self.support_relay = support_relay_protocol;
        self
    }

    #[cfg(feature = "tcp-transport")]
    /// [`Self::build_with_transport`] with a [`Transport`] based on TCP/IP that supports dns resolution and websockets.
    /// It uses [`tokio::spawn`] as executor, hence this method has to be called in the context of a tokio.rs runtime.
    pub async fn build(self) -> Result<StrongholdP2p<Rq, Rs, TRq>, io::Error> {
        let dns_transport = TokioDnsConfig::system(TokioTcpConfig::new())?;
        let transport = dns_transport.clone().or_transport(WsConfig::new(dns_transport));
        let executor = |fut| {
            tokio::spawn(fut);
        };
        self.build_with_transport(transport, executor).await
    }

    /// Create a new [`StrongholdP2p`] instance with an underlying [`Swarm`][libp2p::Swarm] that uses the provided
    /// transport.
    ///
    /// The transport is upgraded with:
    /// - [Relay protocol][`libp2p::relay`]
    /// - Authentication and encryption with the Noise-Protocol, using the XX-handshake
    /// - Yamux substream multiplexing
    ///
    /// The method spawns an event loop in a new task with the provided executor, that handles all interaction with the
    /// Swarm. The loop runs until [`StrongholdP2p`] is dropped, [`StrongholdP2p`] provides an interface to perform
    /// operations in it.
    /// Additionally, the executor is used to configure the
    /// [`SwarmBuilder::executor`][libp2p::swarm::SwarmBuilder::executor].
    ///
    /// ```
    /// # use p2p::{
    ///     firewall::FirewallRules,
    ///     ChannelSinkConfig, EventChannel,  StrongholdP2p, StrongholdP2pBuilder
    /// };
    /// # use futures::channel::mpsc;
    /// # use std::error::Error;
    /// use libp2p::tcp::TokioTcpConfig;
    /// #
    /// # async fn test() -> Result<(), Box<dyn Error>> {
    /// let (firewall_tx, firewall_rx) = mpsc::channel(10);
    /// let (request_tx, request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
    ///
    /// let builder = StrongholdP2pBuilder::new(firewall_tx, request_tx, None, FirewallRules::allow_all());
    /// let p2p: StrongholdP2p<String, String> = builder
    ///     .build_with_transport(TokioTcpConfig::new(), |fut| {
    ///          tokio::spawn(fut);
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build_with_transport<Tp, E>(
        self,
        transport: Tp,
        executor: E,
    ) -> Result<StrongholdP2p<Rq, Rs, TRq>, io::Error>
    where
        Tp: Transport + Sized + Clone + Send + Sync + 'static,
        Tp::Output: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Tp::Dial: Send + 'static,
        Tp::Listener: Send + 'static,
        Tp::ListenerUpgrade: Send + 'static,
        Tp::Error: Send + Sync,
        E: Executor + Send + 'static + Clone,
    {
        // Use the configured keypair or create a new one.
        let (noise_keypair, peer_id) = self.ident.unwrap_or_else(|| {
            let keypair = Keypair::generate_ed25519();
            // Can never fail for `identity::Keypair::Ed25519` and `X25519Spec` protocol.
            let noise_keypair = NoiseKeypair::<X25519Spec>::new().into_authentic(&keypair).unwrap();
            let peer_id = keypair.public().to_peer_id();
            (noise_keypair, peer_id)
        });
        let relay;
        let boxed_transport;
        if self.support_relay {
            let (relay_transport, relay_behaviour) = new_transport_and_behaviour(RelayConfig::default(), transport);
            boxed_transport = relay_transport
                .upgrade(upgrade::Version::V1)
                .authenticate(NoiseConfig::xx(noise_keypair).into_authenticated())
                .multiplex(YamuxConfig::default())
                .boxed();
            relay = Some(relay_behaviour)
        } else {
            boxed_transport = transport
                .upgrade(upgrade::Version::V1)
                .authenticate(NoiseConfig::xx(noise_keypair).into_authenticated())
                .multiplex(YamuxConfig::default())
                .boxed();
            relay = None;
        }
        let mdns = if self.support_mdns {
            Some(Mdns::new(MdnsConfig::default()).await?)
        } else {
            None
        };

        let behaviour = NetworkBehaviour::new(
            self.behaviour_config,
            mdns,
            relay,
            self.firewall_channel,
            self.firewall_rules,
            self.address_info,
        );

        let mut swarm_builder =
            SwarmBuilder::new(boxed_transport, behaviour, peer_id).executor(Box::new(executor.clone()));
        if let Some(limit) = self.connections_limit {
            swarm_builder = swarm_builder.connection_limits(limit.into());
        }
        let swarm = swarm_builder.build();
        let local_peer_id = *swarm.local_peer_id();

        // Channel for sending `SwarmCommand`s.
        let (command_tx, command_rx) = mpsc::channel(10);

        // Spawn an event-loop for all Swarm interaction in new task.
        let event_loop = EventLoop::new(swarm, command_rx, self.requests_channel, self.events_channel);
        executor.exec(event_loop.run().boxed());

        Ok(StrongholdP2p {
            local_peer_id,
            command_tx,
        })
    }
}

/// Inbound Request from a remote peer.
/// It is expected that a response will be returned through the `response_rx` channel,
/// otherwise an [`OutboundFailure`] will occur at the remote peer.
#[derive(Debug)]
pub struct ReceiveRequest<Rq, Rs> {
    /// ID of the request.
    pub request_id: RequestId,
    /// ID of the remote peer that send the request.
    pub peer: PeerId,
    /// Request from the remote peer.
    pub request: Rq,
    /// Channel for returning the response.
    ///
    /// **Note:** If an [`InboundFailure`] occurs before a response was sent, the Receiver side of this channel is
    /// dropped.
    pub response_tx: oneshot::Sender<Rs>,
}

/// Active Listener of the local peer.
#[derive(Debug, Clone)]
pub struct Listener {
    /// The addresses associated with this listener.
    pub addrs: SmallVec<[Multiaddr; 6]>,
    /// Whether it is listening via a relay.
    pub uses_relay: Option<PeerId>,
}

/// Events happening in the Network.
/// Includes events about connection and listener status as well as potential failures when receiving
/// request-response messages.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A failure occurred in the context of receiving an inbound request and sending a response.
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    /// A connection to the given peer has been opened.
    ConnectionEstablished {
        /// Identity of the peer that connected.
        peer: PeerId,
        /// Endpoint of the connection that has been opened.
        endpoint: ConnectedPoint,
        /// Number of established connections to this peer, including the one that has just been
        /// opened.
        num_established: NonZeroU32,
    },
    /// A connection with the given peer has been closed,
    /// possibly as a result of an error.
    ConnectionClosed {
        /// Identity of the peer that disconnected.
        peer: PeerId,
        /// Endpoint of the connection that has been closed.
        endpoint: ConnectedPoint,
        /// Number of other remaining connections to this same peer.
        num_established: u32,
        /// Potential Error that resulted in the disconnection.
        cause: Option<io::Error>,
    },
    /// An error happened on a connection during its initial handshake.
    ///
    /// This can include, for example, an error during the handshake of the encryption layer, or
    /// the connection unexpectedly closed.
    IncomingConnectionError {
        /// Local connection address.
        /// This address has been earlier reported with a [`NewListenAddr`](SwarmEvent::NewListenAddr)
        /// event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
        /// The error that happened.
        error: ConnectionErr,
    },
    /// One of the listeners has reported a new local listening address.
    NewListenAddr(Multiaddr),
    /// One of the listeners has reported the expiration of a listening address.
    ExpiredListenAddr(Multiaddr),
    /// One of the listeners gracefully closed.
    ListenerClosed {
        /// The addresses that the listener was listening on. These addresses are now considered
        /// expired, similar to if a [`ExpiredListenAddr`](SwarmEvent::ExpiredListenAddr) event
        /// has been generated for each of them.
        addresses: Vec<Multiaddr>,
        /// Potential Error in the stream that cause the listener to close.
        cause: Option<io::Error>,
    },
    /// One of the listeners reported a non-fatal error.
    ListenerError {
        /// The listener error.
        error: io::Error,
    },
}

type SwarmEv<Rq, Rs, THandleErr> = SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>;

impl<Rq: Request, Rs: Request, THandleErr> TryFrom<SwarmEv<Rq, Rs, THandleErr>> for NetworkEvent {
    type Error = ();
    fn try_from(value: SwarmEv<Rq, Rs, THandleErr>) -> Result<Self, Self::Error> {
        match value {
            SwarmEvent::Behaviour(BehaviourEvent::InboundFailure {
                request_id,
                peer,
                failure,
            }) => Ok(NetworkEvent::InboundFailure {
                request_id,
                peer,
                failure,
            }),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                concurrent_dial_errors: _,
            } => Ok(NetworkEvent::ConnectionEstablished {
                peer: peer_id,
                num_established,
                endpoint,
            }),
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
            } => {
                let cause = match cause {
                    Some(ConnectionError::IO(e)) => Some(e),
                    _ => None,
                };
                Ok(NetworkEvent::ConnectionClosed {
                    peer: peer_id,
                    num_established,
                    endpoint,
                    cause,
                })
            }
            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
            } => Ok(NetworkEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error: error.into(),
            }),
            SwarmEvent::ExpiredListenAddr { address, .. } => Ok(NetworkEvent::ExpiredListenAddr(address)),
            SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                let cause = match reason {
                    Ok(()) => None,
                    Err(e) => Some(e),
                };
                Ok(NetworkEvent::ListenerClosed { addresses, cause })
            }
            SwarmEvent::ListenerError { error, .. } => Ok(NetworkEvent::ListenerError { error }),
            SwarmEvent::NewListenAddr { address, .. } => Ok(NetworkEvent::NewListenAddr(address)),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLimits {
    max_pending_incoming: Option<u32>,
    max_pending_outgoing: Option<u32>,
    max_established_incoming: Option<u32>,
    max_established_outgoing: Option<u32>,
    max_established_per_peer: Option<u32>,
    max_established_total: Option<u32>,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        ConnectionLimits {
            max_pending_incoming: None,
            max_pending_outgoing: None,
            max_established_incoming: None,
            max_established_outgoing: None,
            max_established_per_peer: Some(5),
            max_established_total: None,
        }
    }
}

impl From<ConnectionLimits> for Libp2pConnectionLimits {
    fn from(l: ConnectionLimits) -> Self {
        Libp2pConnectionLimits::default()
            .with_max_pending_incoming(l.max_pending_incoming)
            .with_max_pending_outgoing(l.max_pending_outgoing)
            .with_max_established_incoming(l.max_established_incoming)
            .with_max_established_outgoing(l.max_established_outgoing)
            .with_max_established_per_peer(l.max_established_per_peer)
            .with_max_established(l.max_established_total)
    }
}

impl ConnectionLimits {
    /// Configures the maximum number of concurrently incoming connections being established.
    pub fn with_max_pending_incoming(mut self, limit: Option<u32>) -> Self {
        self.max_pending_incoming = limit;
        self
    }

    /// Configures the maximum number of concurrently outgoing connections being established.
    pub fn with_max_pending_outgoing(mut self, limit: Option<u32>) -> Self {
        self.max_pending_outgoing = limit;
        self
    }

    /// Configures the maximum number of concurrent established inbound connections.
    pub fn with_max_established_incoming(mut self, limit: Option<u32>) -> Self {
        self.max_established_incoming = limit;
        self
    }

    /// Configures the maximum number of concurrent established outbound connections.
    pub fn with_max_established_outgoing(mut self, limit: Option<u32>) -> Self {
        self.max_established_outgoing = limit;
        self
    }

    /// Configures the maximum number of concurrent established connections (both
    /// inbound and outbound).
    ///
    /// Note: This should be used in conjunction with
    /// [`ConnectionLimits::with_max_established_incoming`] to prevent possible
    /// eclipse attacks (all connections being inbound).
    pub fn with_max_established(mut self, limit: Option<u32>) -> Self {
        self.max_established_total = limit;
        self
    }

    /// Configures the maximum number of concurrent established connections per peer,
    /// regardless of direction (incoming or outgoing).
    pub fn with_max_established_per_peer(mut self, limit: Option<u32>) -> Self {
        self.max_established_per_peer = limit;
        self
    }
}

/// Error on dialing a peer and establishing a connection.
#[derive(Error, Debug)]
pub enum DialErr {
    /// The peer is currently banned.
    #[error("Peer is banned.")]
    Banned,
    /// The configured limit for simultaneous outgoing connections
    /// has been reached.
    #[error("Connection limit: `{limit}`/`{current}`.")]
    ConnectionLimit { limit: u32, current: u32 },
    /// The peer being dialed is the local peer and thus the dial was aborted.
    #[error("Tried to dial local peer id.")]
    LocalPeerId,
    /// No direct or relayed addresses for the peer are known.
    #[error("No addresses known for peer.")]
    NoAddresses,
    /// Pending connection attempt has been aborted.
    #[error(" Pending connection attempt has been aborted.")]
    Aborted,
    /// The peer identity obtained on the connection did not
    /// match the one that was expected.
    #[error("Wrong peer ID, obtained: {obtained:?}")]
    WrongPeerId { obtained: PeerId },
    /// The provided peer identity is invalid.
    #[error("Invalid peer ID: {0:?}")]
    InvalidPeerId(Multihash),
    /// An I/O error occurred on the connection.
    #[error("An I/O error occurred on the connection: {0}.")]
    ConnectionIo(io::Error),
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    #[error("An error occurred while negotiating the transport protocol(s) on a connection: `{0:?}`.")]
    Transport(Vec<(Multiaddr, TransportError<io::Error>)>),
    /// The communication system was shut down before the dialing attempt resolved.
    #[error("The network event-loop was shut down.")]
    Shutdown,
}

impl TryFrom<DialError> for DialErr {
    type Error = ();
    fn try_from(err: DialError) -> Result<Self, Self::Error> {
        let e = match err {
            DialError::Banned => DialErr::Banned,
            DialError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                DialErr::ConnectionLimit { limit, current }
            }
            DialError::LocalPeerId => DialErr::LocalPeerId,
            DialError::WrongPeerId { obtained, .. } => DialErr::WrongPeerId { obtained },
            DialError::InvalidPeerId(hash) => DialErr::InvalidPeerId(hash),
            DialError::DialPeerConditionFalse(_) => return Err(()),
            DialError::Aborted => DialErr::Aborted,
            DialError::ConnectionIo(e) => DialErr::ConnectionIo(e),
            DialError::Transport(addrs) => DialErr::Transport(addrs),
            DialError::NoAddresses => DialErr::NoAddresses,
        };
        Ok(e)
    }
}

/// Error on establishing a connection.
#[derive(Error, Debug)]
pub enum ConnectionErr {
    /// An I/O error occurred on the connection.
    #[error("I/O error: {0}")]
    Io(io::Error),
    /// The peer identity obtained on the connection did not
    /// match the one that was expected.
    #[error("Wrong peer Id, obtained: {obtained:?}")]
    WrongPeerId { obtained: PeerId },

    /// An error occurred while negotiating the transport protocol(s).
    #[error("Transport error: {0}")]
    Transport(TransportErr),
    /// The connection was dropped because the connection limit
    /// for a peer has been reached.
    #[error("Connection limit: `{limit}`/`{current}`.")]
    ConnectionLimit { limit: u32, current: u32 },
    /// Pending connection attempt has been aborted.
    #[error("Pending connection attempt has been aborted.")]
    Aborted,
}

impl From<PendingConnectionError<TransportError<io::Error>>> for ConnectionErr {
    fn from(value: PendingConnectionError<TransportError<io::Error>>) -> Self {
        match value {
            PendingConnectionError::Transport(TransportError::Other(e)) | PendingConnectionError::IO(e) => {
                ConnectionErr::Io(e)
            }
            PendingConnectionError::WrongPeerId { obtained, .. } => ConnectionErr::WrongPeerId { obtained },
            PendingConnectionError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                ConnectionErr::ConnectionLimit { limit, current }
            }
            PendingConnectionError::Transport(err) => ConnectionErr::Transport(err.into()),
            PendingConnectionError::Aborted => ConnectionErr::Aborted,
        }
    }
}

/// Error on the [Transport][libp2p::Transport].
#[derive(Error, Debug)]
pub enum TransportErr {
    /// The address is not supported.
    #[error("Multiaddress not supported: {0}")]
    MultiaddrNotSupported(Multiaddr),
    /// An I/O Error occurred.
    #[error("I/O error: {0}")]
    Io(io::Error),
}

impl From<TransportError<io::Error>> for TransportErr {
    fn from(err: TransportError<io::Error>) -> Self {
        match err {
            TransportError::MultiaddrNotSupported(addr) => TransportErr::MultiaddrNotSupported(addr),
            TransportError::Other(err) => TransportErr::Io(err),
        }
    }
}

/// Error on listening on an address.
#[derive(Error, Debug)]
pub enum ListenErr {
    /// Listening on the address failed on the transport layer.
    #[error("Transport error: {0}")]
    Transport(TransportErr),
    /// The communication system was shut down before the listening attempt resolved.
    #[error("The network event-loop was shut down.")]
    Shutdown,
}

impl From<TransportError<io::Error>> for ListenErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenErr::Transport(err.into())
    }
}

/// Error on listening on a relayed address.
#[derive(Error, Debug)]
pub enum ListenRelayErr {
    /// The relay protocol is not supported.
    #[error("Relay Protocol not enabled.")]
    ProtocolNotSupported,
    /// Establishing a connection to the relay failed.
    #[error("Dial Relay Error: {0}")]
    DialRelay(#[from] DialErr),
    /// Error on listening on an address.
    #[error("Listening Error: {0}")]
    Listen(ListenErr),
}

impl TryFrom<DialError> for ListenRelayErr {
    type Error = <DialErr as TryFrom<DialError>>::Error;
    fn try_from(err: DialError) -> Result<Self, Self::Error> {
        DialErr::try_from(err).map(ListenRelayErr::DialRelay)
    }
}

impl From<TransportError<io::Error>> for ListenRelayErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenRelayErr::Listen(err.into())
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod errors;
mod event_channel;
mod swarm_task;
mod types;

pub use errors::*;
pub use event_channel::{ChannelSinkConfig, EventChannel};
use swarm_task::{SwarmOperation, SwarmTask};
pub use types::*;

use crate::{
    behaviour::{BehaviourEvent, BehaviourState, EstablishedConnections, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallConfiguration, FirewallRequest, FirewallRules, Rule, RuleDirection},
    RelayNotSupported,
};

use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
    AsyncRead, AsyncWrite, FutureExt,
};
use libp2p::{
    core::{connection::ListenerId, transport::Transport, upgrade, Executor, Multiaddr, PeerId},
    identity::Keypair,
    mdns::{Mdns, MdnsConfig},
    noise::{AuthenticKeypair, Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::SwarmBuilder,
    yamux::YamuxConfig,
};
#[cfg(feature = "tcp-transport")]
use libp2p::{dns::TokioDnsConfig, tcp::TokioTcpConfig, websocket::WsConfig};
use std::{borrow::Borrow, io, time::Duration};

#[derive(Clone)]
/// Interface for the stronghold-p2p library to create a swarm, handle events and perform operations.
///
/// All Swarm interaction takes place in a separate task.
/// [`StrongholdP2p`] is essentially a wrapper for the Sender side of a mpsc channel, which is used to initiate
/// operations on the swarm.
///
/// Refer to [`StrongholdP2pBuilder`] for more information on the default configuration.
///
/// ```
/// # use serde::{Serialize, Deserialize};
/// # use p2p::{ChannelSinkConfig, EventChannel, StrongholdP2p};
/// # use futures::channel::mpsc;
/// # use std::borrow::Borrow;
/// #
/// // Type of the requests send to the remote.
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// enum Request {
///     Ping,
///     Message(String),
/// }
///
/// // Trimmed version of the request that is used for validation in the firewall.
/// // In case of `Rule::Ask` this is the message that is bubbled up through the
/// // firewall channel.
/// //
/// // This type is optional but may be needed because e.g. the actual request can not
/// // be cloned, or shouldn't expose details to the receiving side of the firewall-channel.
/// #[derive(Debug, Clone)]
/// enum RequestType {
///     Ping,
///     Message,
/// }
///
/// impl Borrow<RequestType> for Request {
///     fn borrow(&self) -> &RequestType {
///         match self {
///             Request::Ping => &RequestType::Ping,
///             Request::Message(..) => &RequestType::Message,
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
/// // Channel used for dynamic firewall rules:
/// // - If a peer connected for which no rules are present (no default & not peer-specific):
/// //   Allows the user to send back the rules that should be set for this peer.
/// // - If the firewall `Rule` is set to `Rule::Ask`:
/// //   Asks for individual approval for this specific request.
/// let (firewall_tx, firewall_rx) = mpsc::channel(10);
///
/// // Channel trough which inbound requests are forwarded.
/// let (request_tx, request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
///
/// // Optional channel through which current events in the network are sent, e.g.
/// // peers connecting / disconnecting, listener events or non-fatal failures.
/// let (events_tx, events_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
///
/// let p2p = StrongholdP2p::<Request, Response, RequestType>::new(firewall_tx, request_tx, Some(events_tx));
/// ```
pub struct StrongholdP2p<Rq, Rs, TRq = Rq>
where
    // Request message type
    Rq: RqRsMessage + Borrow<TRq>,
    // Response message type
    Rs: RqRsMessage,
    // Optional, tailored request-type that is used in the firewall to get approval.
    // This has the purpose of trimming the actual request down to the firewall-relevant information and e.g. avoid
    // exposing the request's actual content.
    TRq: Clone + Send + 'static,
{
    // Id of the local peer.
    local_peer_id: PeerId,
    // Channel for sending [`SwarmOperation`] to the [`SwarmTask`] .
    // The [`SwarmOperation`]s trigger according operations on the Swarm.
    // The result of an operation is received via the oneshot Receiver that is included in each type.
    command_tx: mpsc::Sender<SwarmOperation<Rq, Rs, TRq>>,
}

impl<Rq, Rs, TRq> StrongholdP2p<Rq, Rs, TRq>
where
    Rq: RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    /// Create a new [`StrongholdP2p`] instance with the default configuration.
    /// Refer to [`StrongholdP2pBuilder::new`] and [`StrongholdP2pBuilder::build`] for detailed information.
    #[cfg(feature = "tcp-transport")]
    pub async fn new(
        firewall_channel: mpsc::Sender<FirewallRequest<TRq>>,
        requests_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
        events_channel: Option<EventChannel<NetworkEvent>>,
    ) -> Result<Self, io::Error> {
        StrongholdP2pBuilder::new(firewall_channel, requests_channel, events_channel)
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
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::SendRequest {
            peer,
            request,
            tx_yield,
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
    /// All active listening addresses for each listener can be obtained from [`StrongholdP2p::get_listeners`]
    pub async fn start_listening(&mut self, address: Multiaddr) -> Result<Multiaddr, ListenErr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StartListening { address, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Start listening via a relay peer on an address following the scheme
    /// `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    pub async fn start_relayed_listening(
        &mut self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ListenRelayErr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StartRelayedListening {
            relay,
            relay_addr,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    //// Currently active listeners.
    pub async fn get_listeners(&mut self) -> Vec<Listener> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetListeners { tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening on all listeners.
    pub async fn stop_listening(&mut self) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StopListening { tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening on the listener associated with the given address.
    pub async fn stop_listening_addr(&mut self, address: Multiaddr) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StopListeningAddr { address, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Stop listening via the given relay.
    pub async fn stop_listening_relay(&mut self, relay: PeerId) -> bool {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StopListeningRelay { relay, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Establish a new new connection to the remote peer.
    /// This will try each known address until either a connection was successful, or all failed.
    pub async fn connect_peer(&mut self, peer: PeerId) -> Result<Multiaddr, DialErr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::ConnectPeer { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Set the default configuration for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub async fn set_firewall_default(&mut self, direction: RuleDirection, default: Rule<TRq>) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::SetFirewallDefault {
            direction,
            default,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get the current default rules for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub async fn get_firewall_default(&mut self) -> FirewallRules<TRq> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetFirewallDefault { tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a default firewall rule.
    /// If there is no default rule and no peer-specific rule, a [`FirewallRequest::PeerSpecificRule`]
    /// request will be sent through the firewall channel
    pub async fn remove_firewall_default(&mut self, direction: RuleDirection) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::RemoveFirewallDefault { direction, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get the explicit rules for a peer, if there are any.
    pub async fn get_peer_rules(&mut self, peer: PeerId) -> FirewallRules<TRq> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetPeerRules { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub async fn set_peer_rule(&mut self, peer: PeerId, direction: RuleDirection, rule: Rule<TRq>) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::SetPeerRule {
            peer,
            direction,
            rule,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a peer specific rule, which will result in using the firewall default rules.
    pub async fn remove_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::RemovePeerRule {
            peer,
            direction,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Get the known addresses for a remote peer.
    pub async fn get_addrs(&mut self, peer: PeerId) -> Vec<Multiaddr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetPeerAddrs { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Add an address for the remote peer.
    pub async fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::AddPeerAddr {
            peer,
            address,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove an address from the known addresses of a remote peer.
    pub async fn remove_address(&mut self, peer: PeerId, address: Multiaddr) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::RemovePeerAddr {
            peer,
            address,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(
        &mut self,
        peer: PeerId,
        address: Option<Multiaddr>,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::AddDialingRelay {
            peer,
            address,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Remove a relay from the list of dialing relays.
    // Returns `false` if the peer was not among the known relays.
    //
    // **Note**: Known relayed addresses for remote peers using this relay will not be influenced by this.
    pub async fn remove_dialing_relay(&mut self, peer: PeerId) -> bool {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::RemoveDialingRelay { peer, tx_yield };
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
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::SetRelayFallback {
            peer,
            use_relay_fallback,
            tx_yield,
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
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::UseSpecificRelay {
            target,
            relay,
            is_exclusive,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Bans a peer by its peer ID.
    ///
    /// Any incoming connection and any dialing attempt will immediately be rejected.
    /// This function has no effect if the peer is already banned.
    pub async fn ban_peer(&mut self, peer: PeerId) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::BanPeer { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Unbans a peer.
    pub async fn unban_peer(&mut self, peer: PeerId) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::UnbanPeer { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Check whether the Network has an established connection to a peer.
    pub async fn is_connected(&mut self, peer: PeerId) -> bool {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetIsConnected { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    // Get currently established connections.
    pub async fn get_connections(&mut self) -> Vec<(PeerId, EstablishedConnections)> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetConnections { tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    // Export the firewall configuration and address info.
    pub async fn export_state(&mut self) -> BehaviourState<TRq> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::ExportConfig { tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    async fn send_command(&mut self, command: SwarmOperation<Rq, Rs, TRq>) {
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
/// - All outbound requests are permitted
/// - No firewall rules for inbound requests are set. In case of an inbound requests, a
///   [`FirewallRequest::PeerSpecificRule`] request is sent through the `firewall_channel` to specify the rules for this
///   peer.
/// - A new keypair is created and used, from which the [`PeerId`] of the local peer is derived.
/// - No limit for simultaneous connections.
/// - Request-timeout and Connection-timeout are 10s.
/// - [`Mdns`][`libp2p::mdns`] protocol is enabled. **Note**: This also broadcasts our own address and id to the local
///   network.
/// - [`Relay`][`libp2p::relay`] protocol is supported. *Note:* This also means that other peers can use our peer as
///   relay.
///
/// `StrongholdP2p` is build either via [`StrongholdP2pBuilder::build`] (requires feature **tcp-transport**) with a
/// pre-configured transport, or [`StrongholdP2pBuilder::build_with_transport`] with a custom transport.
///
/// When building a new `StrongholdP2p` a new [`Swarm`][libp2p::Swarm] is created and continuously polled for events.
/// Inbound requests are forwarded through a mpsc::channel<ReceiveRequest<Rq, Rs>>.
/// Optionally all events regarding connections and listeners are forwarded as [`NetworkEvent`].
pub struct StrongholdP2pBuilder<Rq, Rs, TRq = Rq>
where
    Rq: RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    firewall_channel: mpsc::Sender<FirewallRequest<TRq>>,
    requests_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
    events_channel: Option<EventChannel<NetworkEvent>>,

    // Use an existing keypair instead of creating a new one.
    ident: Option<(AuthenticKeypair<X25519Spec>, PeerId)>,

    // Configuration of the underlying [`NetBehaviour`].
    behaviour_config: NetBehaviourConfig,

    // Limit of simultaneous connections.
    connections_limit: Option<ConnectionLimits>,

    // Firewall config and list of known addresses that were persisted from a former running instance.
    state: Option<BehaviourState<TRq>>,

    // Default rules for the firewall.
    default_rules: Option<FirewallRules<TRq>>,

    // Use Mdns protocol for peer discovery in the local network.
    //
    // Note: This also broadcasts our own address and id to the local network.
    support_mdns: bool,

    support_relay: bool,
}

impl<Rq, Rs, TRq> StrongholdP2pBuilder<Rq, Rs, TRq>
where
    Rq: RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
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
    ) -> Self {
        let default_rules = FirewallRules::new(None, Some(Rule::AllowAll));
        StrongholdP2pBuilder {
            firewall_channel,
            requests_channel,
            events_channel,
            ident: None,
            behaviour_config: Default::default(),
            connections_limit: None,
            default_rules: Some(default_rules),
            support_mdns: true,
            support_relay: true,
            state: None,
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

    /// Load the behaviour state from a former running instance.
    /// The state contains default and peer-specific rules, and the list of known addresses for remote peers.
    pub fn load_state(mut self, state: BehaviourState<TRq>) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the default firewall rules, which apply for all requests from/ to peers for which no peer-specific rule was
    /// set. Per default in the firewall, no rules are set and a [`FirewallRequest::PeerSpecificRule`] request is
    /// sent through the `firewall_channel` when a peer connect or an inbound/ outbound request is sent.
    ///
    /// **Note**: If former firewall config was loaded via `StrongholdP2pBuilder::load_state` the default rules will be
    /// overwritten with this method.
    pub fn with_firewall_default(mut self, rules: FirewallRules<TRq>) -> Self {
        self.default_rules = Some(rules);
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
    /// - [Relay protocol][<https://docs.libp2p.io/concepts/circuit-relay/>]
    /// - Authentication and encryption with the Noise-Protocol, using the XX-handshake
    /// - Yamux substream multiplexing
    ///
    /// The method spawns a new task with the provided executor, that handles all interaction with the Swarm.
    /// The task runs until [`StrongholdP2p`] is dropped, [`StrongholdP2p`] provides an interface to perform
    /// operations on the swarm-task.
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
    /// let builder = StrongholdP2pBuilder::new(firewall_tx, request_tx, None)
    ///     .with_firewall_default(FirewallRules::allow_all());
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
        let (address_info, mut firewall) = match self.state {
            Some(state) => (Some(state.address_info), state.firewall),
            None => (None, FirewallConfiguration::default()),
        };
        if let Some(rules) = self.default_rules {
            firewall.default = rules;
        }

        let behaviour = NetBehaviour::new(
            self.behaviour_config,
            mdns,
            relay,
            self.firewall_channel,
            firewall,
            address_info,
        );

        let mut swarm_builder =
            SwarmBuilder::new(boxed_transport, behaviour, peer_id).executor(Box::new(executor.clone()));
        if let Some(limit) = self.connections_limit {
            swarm_builder = swarm_builder.connection_limits(limit.into());
        }
        let swarm = swarm_builder.build();
        let local_peer_id = *swarm.local_peer_id();

        // Channel for sending `SwarmOperation`s.
        let (command_tx, command_rx) = mpsc::channel(10);

        // Spawn a new task responsible for all Swarm interaction.
        let swarm_task = SwarmTask::new(swarm, command_rx, self.requests_channel, self.events_channel);
        executor.exec(swarm_task.run().boxed());

        Ok(StrongholdP2p {
            local_peer_id,
            command_tx,
        })
    }
}

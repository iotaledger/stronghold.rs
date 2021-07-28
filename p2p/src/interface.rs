// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod errors;
mod msg_channel;
mod swarm_task;
mod types;
use self::swarm_task::{SwarmOperation, SwarmTask};
use crate::{
    behaviour::{BehaviourEvent, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallConfiguration, FirewallRequest, FirewallRules, Rule, RuleDirection},
    Keypair,
};
pub use errors::*;
use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
    AsyncRead, AsyncWrite, FutureExt,
};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsConfig};
#[cfg(feature = "relay")]
use libp2p::relay::{new_transport_and_behaviour, RelayConfig};
use libp2p::{
    core::{
        connection::{ConnectionLimits, ListenerId},
        transport::Transport,
        upgrade, Executor, Multiaddr, PeerId,
    },
    noise::{AuthenticKeypair, Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    swarm::SwarmBuilder,
    yamux::YamuxConfig,
};
#[cfg(feature = "tcp-transport")]
use libp2p::{dns::TokioDnsConfig, tcp::TokioTcpConfig, websocket::WsConfig};
pub use msg_channel::{ChannelSinkConfig, EventChannel};
#[cfg(feature = "tcp-transport")]
use std::io;
use std::{borrow::Borrow, time::Duration};
pub use types::*;

#[derive(Clone)]
/// Interface for the stronghold-p2p library to create a swarm, handle events and perform operations.
///
/// All Swarm interaction takes place in a separate task.
/// [`StrongholdP2p`] is essentially a wrapper for the Sender side of a mpsc channel, which is used to initiate
/// operations on the swarm.
///
/// Refer to [`StrongholdP2pBuilder`] for more information on the default configuration.
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
    pub fn get_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Send a new request to a remote peer.
    ///
    /// This will attempt to establish a connection to the remote via one of the known addresses, if there is no active
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
    /// Note: Depending on the used transport, this may produce multiple listening addresses.
    /// This method only returns the first reported listening address for the new listener.
    /// All active listening addresses for each listener can be obtained from [`StrongholdP2p::get_listeners`]
    pub async fn start_listening(&mut self, address: Multiaddr) -> Result<Multiaddr, ListenErr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::StartListening { address, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    #[cfg(feature = "relay")]
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

    #[cfg(feature = "relay")]
    /// Stop listening via the given relay.
    pub async fn stop_listening_relay(&mut self, relay: PeerId) {
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
    pub async fn get_peer_rules(&mut self, peer: PeerId) -> Option<FirewallRules<TRq>> {
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

    #[cfg(feature = "relay")]
    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::AddDialingRelay {
            peer,
            address,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    #[cfg(feature = "relay")]
    /// Remove a relay from the list of dialing relays.
    pub async fn remove_dialing_relay(&mut self, peer: PeerId) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::RemoveDialingRelay { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    #[cfg(feature = "relay")]
    /// Configure whether it should be attempted to reach the remote via known relays, if it can not be reached via
    /// known addresses.
    pub async fn set_relay_fallback(&mut self, peer: PeerId, use_relay_fallback: bool) {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::SetRelayFallback {
            peer,
            use_relay_fallback,
            tx_yield,
        };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    #[cfg(feature = "relay")]
    /// Dial the target via the specified relay.
    /// The `is_exclusive` parameter specifies whether other known relays should be used if using the set relay is not
    /// successful.
    ///
    /// Returns the relayed address of the local peer (`<relay-addr>/<relay-id>/p2p-circuit/<local-id>),
    /// if an address for the relay is known.
    pub async fn use_specific_relay(&mut self, target: PeerId, relay: PeerId, is_exclusive: bool) -> Option<Multiaddr> {
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

    async fn send_command(&mut self, command: SwarmOperation<Rq, Rs, TRq>) {
        let _ = poll_fn(|cx| self.command_tx.poll_ready(cx)).await;
        let _ = self.command_tx.start_send(command);
    }
}

/// Use existing keypair for authentication on the transport layer.
///
/// The local [`PeerId`] is derived from public key of the IdKeys.
/// If this is not the case, remote Peers will reject the communication.
pub enum InitKeypair {
    /// Identity Keys that are used to derive the noise keypair and peer id.
    IdKeys(Keypair),
    /// Use authenticated noise-keypair.
    /// **Note**: The peer-id has to be derived from the same keypair that is used to create the noise-keypair.
    Authenticated {
        peer_id: PeerId,
        noise_keypair: AuthenticKeypair<X25519Spec>,
    },
}

/// Builder for new `StrongholdP2p`.
///
/// Default behaviour:
/// - No firewall rules are set. In case of inbound / outbound requests, a [`FirewallRequest::PeerSpecificRule`] request
///   is sent through the `firewall_channel` to specify the rules for this peer.
/// - A new keypair is created and used, from which the [`PeerId`] of the local peer is derived.
/// - No limit for simultaneous connections.
/// - Request-timeout and Connection-timeout are 10s.
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
    behaviour_config: NetBehaviourConfig<TRq>,

    // Limit of simultaneous connections.
    connections_limit: Option<ConnectionLimits>,
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
        StrongholdP2pBuilder {
            firewall_channel,
            requests_channel,
            events_channel,
            ident: None,
            behaviour_config: Default::default(),
            connections_limit: None,
        }
    }

    /// Set the keypair that is used for authenticating the communication on the transport layer.
    /// The local [`PeerId`] is derived from the keypair.
    pub fn with_keys(mut self, keys: InitKeypair) -> Self {
        let (keypair, id) = match keys {
            InitKeypair::IdKeys(keypair) => {
                let noise_keypair = NoiseKeypair::<X25519Spec>::new().into_authentic(&keypair).unwrap();
                let id = keypair.public().into_peer_id();
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

    /// Set the firewall configuration.
    /// The peer-specific rules overwrite the default rules for that peer.
    ///
    /// Per default, no rules are set and a [`FirewallRequest::PeerSpecificRule`] request is sent through the
    /// `firewall_channel` when a peer connect or an inbound/ outbound request is sent.
    pub fn with_firewall_config(mut self, config: FirewallConfiguration<TRq>) -> Self {
        self.behaviour_config.firewall = config;
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
        Ok(self.build_with_transport(transport, executor).await)
    }

    /// Create a new [`StrongholdP2p`] instance with an underlying [`Swarm`][libp2p::Swarm] that uses the provided
    /// transport.
    ///
    /// The transport is upgraded with:
    /// - [Relay protocol][<https://docs.libp2p.io/concepts/circuit-relay/>] (requires *feature = "relay"*)
    /// - Authentication and encryption with the Noise-Protocol, using the XX-handshake
    /// - Yamux substream multiplexing
    ///
    /// The method spawns a new task with the provided executor, that handles all interaction with the Swarm.
    /// The task runs until [`StrongholdP2p`] is dropped, [`StrongholdP2p`] provides an interface to perform
    /// operations on the swarm-task.
    /// Additionally, the executor is used to configure the
    /// [`SwarmBuilder::executor`][libp2p::swarm::SwarmBuilder::executor].
    pub async fn build_with_transport<Tp, E>(self, transport: Tp, executor: E) -> StrongholdP2p<Rq, Rs, TRq>
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
            let noise_keypair = NoiseKeypair::<X25519Spec>::new().into_authentic(&keypair).unwrap();
            let peer_id = keypair.public().into_peer_id();
            (noise_keypair, peer_id)
        });
        #[cfg(feature = "relay")]
        let (transport, relay_behaviour) = new_transport_and_behaviour(RelayConfig::default(), transport);
        let transport = transport
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keypair).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed();
        #[cfg(feature = "mdns")]
        let mdns = Mdns::new(MdnsConfig::default())
            .await
            .expect("Failed to create mdns behaviour.");
        let behaviour = NetBehaviour::new(
            self.behaviour_config,
            #[cfg(feature = "mdns")]
            mdns,
            #[cfg(feature = "relay")]
            relay_behaviour,
            self.firewall_channel,
        );

        let mut swarm_builder = SwarmBuilder::new(transport, behaviour, peer_id).executor(Box::new(executor.clone()));
        if let Some(limit) = self.connections_limit {
            swarm_builder = swarm_builder.connection_limits(limit);
        }
        let swarm = swarm_builder.build();
        let local_peer_id = *swarm.local_peer_id();

        // Channel for sending `SwarmOperation`s.
        let (command_tx, command_rx) = mpsc::channel(10);

        // Spawn a new task responsible for all Swarm interaction.
        let swarm_task = SwarmTask::new(swarm, command_rx, self.requests_channel, self.events_channel);
        executor.exec(swarm_task.run().boxed());

        StrongholdP2p {
            local_peer_id,
            command_tx,
        }
    }
}

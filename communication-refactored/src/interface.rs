// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod errors;
mod swarm_task;
mod types;
use crate::{
    behaviour::{BehaviourEvent, NetBehaviour, NetBehaviourConfig},
    firewall::{
        FirewallConfiguration, FirewallRequest, FirewallRules, Rule, RuleDirection, ToPermissionVariants,
        VariantPermission,
    },
    Keypair,
};
pub use errors::*;
use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
    AsyncRead, AsyncWrite,
};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsConfig};
#[cfg(feature = "relay")]
use libp2p::relay::{new_transport_and_behaviour, RelayConfig};
use libp2p::{
    core::{
        connection::{ConnectionLimits, ListenerId},
        transport::Transport,
        upgrade, Multiaddr, PeerId,
    },
    noise::{AuthenticKeypair, Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    swarm::SwarmBuilder,
    yamux::YamuxConfig,
};
#[cfg(feature = "tcp-transport")]
use libp2p::{dns::TokioDnsConfig, tcp::TokioTcpConfig, websocket::WsConfig};
#[cfg(feature = "tcp-transport")]
use std::io;
use std::{fmt::Debug, marker::PhantomData, time::Duration};

pub use types::*;

use self::swarm_task::{SwarmOperation, SwarmTask};

/// Use existing keypair for authentication on the transport layer.
///
/// The local [`PeerId`] is derived from public key of the IdKeys.
/// If this is not the case, remote Peers will reject the communication.
pub enum InitKeypair {
    /// Identity Keys that are be used to derive the noise keypair and peer id.
    IdKeys(Keypair),
    /// Use authenticated noise-keypair.
    /// **Note**: The peer-id has to be derived from the same keypair that is used to create the noise-keypair.
    Authenticated {
        peer_id: PeerId,
        noise_keypair: AuthenticKeypair<X25519Spec>,
    },
}

pub struct ShCommunicationBuilder<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    ask_firewall_chan: mpsc::Sender<FirewallRequest<P>>,
    inbound_req_chan: mpsc::Sender<ReceiveRequest<Rq, Rs>>,
    net_events_chan: Option<mpsc::Sender<NetworkEvent>>,

    // Use an existing keypair instead of creating a new one.
    ident: Option<(AuthenticKeypair<X25519Spec>, PeerId)>,

    // Configuration of the underlying [`NetBehaviour`].
    behaviour_config: NetBehaviourConfig,

    // Limit of simultaneous connections.
    connections_limit: Option<ConnectionLimits>,
}

impl<Rq, Rs, P> ShCommunicationBuilder<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    pub fn new(
        ask_firewall_chan: mpsc::Sender<FirewallRequest<P>>,
        inbound_req_chan: mpsc::Sender<ReceiveRequest<Rq, Rs>>,
        net_events_chan: Option<mpsc::Sender<NetworkEvent>>,
    ) -> Self {
        ShCommunicationBuilder {
            ask_firewall_chan,
            inbound_req_chan,
            net_events_chan,
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

    pub fn with_connection_timeout(mut self, t: Duration) -> Self {
        self.behaviour_config.connection_timeout = t;
        self
    }

    pub fn with_firewall_config(mut self, config: FirewallConfiguration) -> Self {
        self.behaviour_config.firewall = config;
        self
    }

    #[cfg(feature = "tcp-transport")]
    pub async fn build(self) -> Result<ShCommunication<Rq, Rs, P>, io::Error> {
        let dns_transport = TokioDnsConfig::system(TokioTcpConfig::new())?;
        let transport = dns_transport.clone().or_transport(WsConfig::new(dns_transport));
        Ok(self.build_with_transport(transport).await)
    }

    /// Create a new [`ShCommunication`] instance with an underlying [`Swarm`] that uses the provided transport.
    /// This spawns a new task that handles all ineraction with the Swarm, this task runs until [`ShCommunication`] is
    /// dropped.
    pub async fn build_with_transport<T>(self, transport: T) -> ShCommunication<Rq, Rs, P>
    where
        T: Transport + Sized + Clone + Send + Sync + 'static,
        T::Output: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T::Dial: Send + 'static,
        T::Listener: Send + 'static,
        T::ListenerUpgrade: Send + 'static,
        T::Error: Send + Sync,
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
            self.ask_firewall_chan,
        );
        let mut swarm_builder = SwarmBuilder::new(transport, behaviour, peer_id).executor(Box::new(|fut| {
            tokio::spawn(fut);
        }));
        if let Some(limit) = self.connections_limit {
            swarm_builder = swarm_builder.connection_limits(limit);
        }
        let swarm = swarm_builder.build();
        let local_peer_id = *swarm.local_peer_id();

        let (command_tx, command_rx) = mpsc::channel(10);
        let swarm_task = SwarmTask::new(swarm, command_rx, self.inbound_req_chan, self.net_events_chan);
        tokio::spawn(swarm_task.run());

        ShCommunication {
            local_peer_id,
            command_tx,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
/// Interface for the stronghold-communication library to create a swarm, handle events and perform operations.
///
/// All Swarm interaction takes place in a separate task.
/// [`ShCommunication`] is essentially a wrapper for the Sender side of channel, which is used to initiate operations on
/// the swarm.
pub struct ShCommunication<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    local_peer_id: PeerId,
    command_tx: mpsc::Sender<SwarmOperation<Rq, Rs>>,
    _marker: PhantomData<P>,
}

impl<Rq, Rs, P> ShCommunication<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    /// Spawn a new task for with a new [`Swarm`].
    /// Create a new ShCommunication instance to initiate operations on the Swarm.
    ///
    /// Parameters:
    /// - `ask_firewall_chan`: Channel for [`FirewallRequest`] if there are no fixed rules in the firewall or
    ///   [`Rule::Ask`] was set.
    /// - `inbound_req_chan`: Channel for forwarding inbound requests from remote peers
    /// - `net_events_chan`: Optional channel for forwarding all events in the swarm.
    #[cfg(feature = "tcp-transport")]
    pub async fn new(
        ask_firewall_chan: mpsc::Sender<FirewallRequest<P>>,
        inbound_req_chan: mpsc::Sender<ReceiveRequest<Rq, Rs>>,
        net_events_chan: Option<mpsc::Sender<NetworkEvent>>,
    ) -> Result<Self, io::Error> {
        ShCommunicationBuilder::new(ask_firewall_chan, inbound_req_chan, net_events_chan)
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
    /// The response or a potential failure will be returned through the [`ResponseReceiver.response_rx`] channel.
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

    /// Start listening on the network.
    /// If no address is given, the listening address will be OS-assigned.
    pub async fn start_listening(&mut self, address: Option<Multiaddr>) -> Result<Multiaddr, ListenErr> {
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
    pub async fn set_firewall_default(&mut self, direction: RuleDirection, default: Rule) {
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
    pub async fn get_firewall_default(&mut self) -> FirewallRules {
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
    pub async fn get_peer_rules(&mut self, peer: PeerId) -> Option<FirewallRules> {
        let (tx_yield, rx_yield) = oneshot::channel();
        let command = SwarmOperation::GetPeerRules { peer, tx_yield };
        self.send_command(command).await;
        rx_yield.await.unwrap()
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub async fn set_peer_rule(&mut self, peer: PeerId, direction: RuleDirection, rule: Rule) {
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

    async fn send_command(&mut self, command: SwarmOperation<Rq, Rs>) {
        let _ = poll_fn(|cx| self.command_tx.poll_ready(cx)).await;
        let _ = self.command_tx.start_send(command);
    }
}

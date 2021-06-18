// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod errors;
mod types;
use crate::{
    behaviour::{BehaviourEvent, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallRequest, FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    Keypair,
};
use async_std::task::{self, Context};
pub use errors::*;
use futures::{
    channel::{mpsc::Sender, oneshot},
    future::poll_fn,
    FutureExt,
};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsConfig};
use libp2p::{
    core::{connection::ListenerId, transport::Transport, upgrade, Multiaddr, PeerId},
    multiaddr::Protocol,
    noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Debug,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};
pub use types::*;

/// Active Listener of the local peer.
pub struct Listener {
    /// The addresses associated with this listener.
    pub addrs: SmallVec<[Multiaddr; 6]>,
    /// Whether the listener uses a relay.
    pub uses_relay: Option<PeerId>,
}

/// Interface for the stronghold-communication library to create a swarm, handle events and perform operations.
pub struct ShCommunication<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    task_handle: JoinHandle<()>,
    shutdown_chan: oneshot::Sender<()>,
    swarm: Arc<Mutex<Swarm<NetBehaviour<Rq, Rs, P>>>>,
    listeners: HashMap<ListenerId, Listener>,
    request_chan: Sender<ReceiveRequest<Rq, Rs>>,
    net_events_chan: Option<Sender<NetworkEvents>>,
}

impl<Rq, Rs, P> ShCommunication<Rq, Rs, P>
where
    Rq: Debug + RqRsMessage + ToPermissionVariants<P>,
    Rs: Debug + RqRsMessage,
    P: VariantPermission,
{
    /// Create a new ShCommunication instance and spawn the [`Swarm`].
    ///
    /// Parameters:
    /// - `keypair`: The keypair used for noise authentication and to derive the [`PeerId`]
    /// - `config`: Configuration for the underlying network behaviour protocol
    /// - `ask_firewall_chan`: Channel for firewall requests if there are no fixed rule or [`Rule::Ask`] was set
    /// - `inbound_req_chan`: Channel for receiving inbound requests from remote peers
    /// - `net_events_chan`: Optional channel for receiving all events in the network.
    pub async fn new(
        keypair: Keypair,
        config: NetBehaviourConfig,
        ask_firewall_chan: Sender<FirewallRequest<P>>,
        inbound_req_chan: Sender<ReceiveRequest<Rq, Rs>>,
        net_events_chan: Option<Sender<NetworkEvents>>,
    ) -> Self {
        let peer = keypair.public().into_peer_id();
        let noise_keys = NoiseKeypair::<X25519Spec>::new().into_authentic(&keypair).unwrap();
        let (relay_transport, relay_behaviour) =
            new_transport_and_behaviour(RelayConfig::default(), TcpConfig::new().nodelay(true));
        let transport = relay_transport
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed();
        #[cfg(feature = "mdns")]
        let mdns = Mdns::new(MdnsConfig::default())
            .await
            .expect("Failed to create mdns behaviour.");
        let behaviour = NetBehaviour::new(
            config,
            #[cfg(feature = "mdns")]
            mdns,
            relay_behaviour,
            ask_firewall_chan,
        );
        let swarm = Swarm::new(transport, behaviour, peer);

        let swarm_rw_lock = Arc::new(Mutex::new(swarm));
        let rw_lock_clone = Arc::clone(&swarm_rw_lock);
        let inbound_req_chan_clone = inbound_req_chan.clone();
        let net_events_chan_clone = net_events_chan.clone();

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let task_handle = thread::spawn(move || {
            Self::run(
                rw_lock_clone,
                inbound_req_chan_clone,
                net_events_chan_clone,
                shutdown_rx,
            )
        });

        ShCommunication {
            task_handle,
            swarm: swarm_rw_lock,
            listeners: HashMap::new(),
            request_chan: inbound_req_chan,
            net_events_chan,
            shutdown_chan: shutdown_tx,
        }
    }

    /// Shutdown the swarm and all network interaction.
    pub fn shutdown(mut self) {
        drop(self.shutdown_chan);
        self.request_chan.close_channel();
        let _ = self.task_handle.join();
    }

    /// Get the [`PeerId`] of the local peer.
    pub fn get_peer_id(&self) -> PeerId {
        let swarm = self.swarm.lock().unwrap();
        *swarm.local_peer_id()
    }

    /// Send a new request to a remote peer.
    ///
    /// This will attempt to establish a connection to the remote via one of the known addresses, if there is no active
    /// connection.
    pub fn send_request(&self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().send_request(peer, request)
    }

    /// Start listening on the network.
    /// If no address is given, the listening address will be OS-assigned.
    pub async fn start_listening(&mut self, address: Option<Multiaddr>) -> Result<Multiaddr, TransportErr> {
        let mut swarm = self.swarm.lock().unwrap();
        let a = address.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."));
        let listener_id = swarm.listen_on(a).map_err(TransportErr::from)?;
        loop {
            let event = swarm.next_event().await;
            match event {
                SwarmEvent::NewListenAddr(ref addr) => {
                    let addr = addr.clone();
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event);
                    return Ok(addr);
                }
                _ => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event),
            }
        }
    }

    /// Start listening via a relay peer on an address following the scheme
    /// `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    pub async fn start_relayed_listening(
        &mut self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ListenRelayErr> {
        if let Some(addr) = relay_addr {
            self.add_address(relay, addr);
        }
        let relay_addr = self.dial_peer(&relay).await.map_err(ListenRelayErr::from)?;

        let mut swarm = self.swarm.lock().unwrap();
        let local_id = *swarm.local_peer_id();
        let relayed_addr = relay_addr
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(local_id.into()));
        let listener_id = swarm.listen_on(relayed_addr.clone()).map_err(ListenRelayErr::from)?;
        loop {
            let event = swarm.next_event().await;
            match event {
                SwarmEvent::NewListenAddr(ref addr) if addr == &relayed_addr => {
                    let addr = addr.clone();
                    Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event);
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    return Ok(addr);
                }
                _ => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event),
            }
        }
    }

    /// Currently active listeners.
    pub fn get_listeners(&self) -> Vec<&Listener> {
        self.listeners.values().collect()
    }

    /// Stop listening on all listeners.
    pub fn stop_listening(&mut self) {
        let mut swarm = self.swarm.lock().unwrap();
        for (listener_id, _) in self.listeners.drain() {
            let _ = swarm.remove_listener(listener_id);
        }
    }

    /// Stop listening on the listener associated with the given address.
    pub fn stop_listening_addr(&mut self, addr: Multiaddr) {
        let mut remove_listeners = Vec::new();
        for (id, listener) in self.listeners.iter() {
            if listener.addrs.contains(&addr) {
                remove_listeners.push(*id);
            }
        }
        for id in remove_listeners {
            let _ = self.listeners.remove(&id);
        }
    }

    /// Stop listening via the given relay.
    pub fn stop_listening_relay(&mut self, relay: PeerId) {
        let mut remove_listeners = Vec::new();
        for (id, listener) in self.listeners.iter() {
            if listener.uses_relay == Some(relay) {
                remove_listeners.push(*id);
            }
        }
        for id in remove_listeners {
            let _ = self.listeners.remove(&id);
        }
    }

    /// Establish a new new connection to the remote peer.
    /// This will try each known address until either a connection was successful, or all failed.
    pub async fn dial_peer(&self, peer: &PeerId) -> Result<Multiaddr, DialErr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.dial(peer).map_err(DialErr::from)?;
        loop {
            let event = swarm.next_event().await;
            match event {
                SwarmEvent::ConnectionEstablished {
                    peer_id, ref endpoint, ..
                } if &peer_id == peer => {
                    let remote_addr = endpoint.get_remote_address().clone();
                    Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event);
                    return Ok(remote_addr);
                }
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    attempts_remaining: 0,
                    ..
                } if &peer_id == peer => return Err(DialErr::UnreachableAddrs),
                _ => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event),
            }
        }
    }

    /// Set the default configuration for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub fn set_firewall_default(&self, direction: RuleDirection, default: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_firewall_default(direction, default)
    }

    /// Get the current default rules for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub fn get_firewall_default(&self) -> FirewallRules {
        let swarm = self.swarm.lock().unwrap();
        swarm.behaviour().get_firewall_default().clone()
    }

    /// Remove a default firewall rule.
    /// If there is no default rule and no peer-specific rule, a [`FirewallRequest::PeerSpecificRule`]
    /// request will be sent through the firewall channel
    pub fn remove_firewall_default(&self, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_firewall_default(direction)
    }

    /// Get the explicit rules for a peer, if there are any.
    pub fn get_peer_rules(&self, peer: &PeerId) -> Option<FirewallRules> {
        let swarm = self.swarm.lock().unwrap();
        swarm.behaviour().get_peer_rules(peer).cloned()
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub fn set_peer_rule(&self, peer: PeerId, direction: RuleDirection, rule: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_peer_rule(peer, direction, rule)
    }

    /// Remove a peer specific rule, which will result in using the firewall default rules.
    pub fn remove_peer_rule(&self, peer: PeerId, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_peer_rule(peer, direction)
    }

    /// Get the known addresses for a remote peer.
    pub fn get_addrs(&self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().addresses_of_peer(peer)
    }

    /// Add an address for the remote peer.
    pub fn add_address(&self, peer: PeerId, address: Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_address(peer, address)
    }

    /// Remove an address from the known addresses of a remote peer.
    pub fn remove_address(&self, peer: &PeerId, address: &Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_address(peer, address)
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub fn add_dialing_relay(&self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_dialing_relay(peer, address)
    }

    /// Remove a relay from the list of dialing relays.
    pub fn remove_dialing_relay(&self, peer: &PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_dialing_relay(peer)
    }

    /// Configure whether it should be attempted to reach the remote via known relays, if it can not be reached via
    /// known addresses.
    pub fn set_relay_fallback(&self, peer: PeerId, use_relay_fallback: bool) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_relay_fallback(peer, use_relay_fallback);
    }

    /// Dial the target via the specified relay.
    /// The `is_exclusive` specifies whether other known relays should be used if using the set relay is not successful.
    ///
    /// Returns the relayed address of the local peer (`<relay-addr>/<relay-id>/p2p-circuit/<local-id>),
    /// if an address for the relay is known.
    pub fn use_specific_relay(&mut self, target: PeerId, relay: PeerId, is_exclusive: bool) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().use_specific_relay(target, relay, is_exclusive)
    }

    /// Bans a peer by its peer ID.
    ///
    /// Any incoming connection and any dialing attempt will immediately be rejected.
    /// This function has no effect if the peer is already banned.
    pub fn ban_peer(&self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.ban_peer_id(peer);
    }

    /// Unbans a peer.
    pub fn unban_peer(&self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.unban_peer_id(peer);
    }

    /// Checks whether the `Network` has an established connection to a peer.
    pub fn is_connected(&self, peer: &PeerId) -> bool {
        let swarm = self.swarm.lock().unwrap();
        swarm.is_connected(peer)
    }

    fn handle_swarm_event<THandleErr>(
        mut request_channel: Sender<ReceiveRequest<Rq, Rs>>,
        net_events_chan: Option<Sender<NetworkEvents>>,
        event: SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>,
    ) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Request(r)) => {
                task::spawn(async move {
                    let _ = poll_fn(|cx: &mut Context| request_channel.poll_ready(cx))
                        .await
                        .unwrap();
                    let _ = request_channel.start_send(r);
                });
            }
            other => {
                if let Ok(ev) = NetworkEvents::try_from(other) {
                    if let Some(mut channel) = net_events_chan {
                        task::spawn(async move {
                            let _ = poll_fn(|cx: &mut Context| channel.poll_ready(cx)).await;
                            let _ = channel.start_send(ev);
                        });
                    }
                }
            }
        }
    }

    /// Poll the swarm in a loop until [`ShCommunication`] is shut down and the shutdown-channel is dropped.
    fn run(
        swarm_mutex: Arc<Mutex<Swarm<NetBehaviour<Rq, Rs, P>>>>,
        request_channel: Sender<ReceiveRequest<Rq, Rs>>,
        net_events_chan: Option<Sender<NetworkEvents>>,
        mut shutdown_chan: oneshot::Receiver<()>,
    ) {
        while shutdown_chan.try_recv().is_ok() {
            if let Ok(mut swarm) = swarm_mutex.lock() {
                if let Some(event) = swarm.next_event().now_or_never() {
                    Self::handle_swarm_event(request_channel.clone(), net_events_chan.clone(), event);
                }
            }
        }
    }
}

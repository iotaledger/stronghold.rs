// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// mod swarm;
use crate::{
    behaviour::{BehaviourEvent, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallRequest, FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    Keypair, NetworkEvents, ReceiveRequest, ResponseReceiver, RqRsMessage,
};
use async_std::task::{self, Context};
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
    swarm::{DialError, NetworkBehaviour, Swarm, SwarmEvent},
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

pub struct Listener {
    addrs: SmallVec<[Multiaddr; 6]>,
    uses_relay: Option<PeerId>,
}

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

    pub fn shutdown(mut self) {
        drop(self.shutdown_chan);
        self.request_chan.close_channel();
        let _ = self.task_handle.join();
    }

    pub fn get_peer_id(&self) -> PeerId {
        let swarm = self.swarm.lock().unwrap();
        *swarm.local_peer_id()
    }

    pub fn send_request(&self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().send_request(peer, request)
    }

    pub async fn start_listening(&mut self, address: Option<Multiaddr>) -> Result<Multiaddr, ()> {
        let mut swarm = self.swarm.lock().unwrap();
        let a = address.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."));
        let listener_id = swarm.listen_on(a).map_err(|_| ())?;
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

    pub async fn start_relayed_listening(
        &mut self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> Result<Multiaddr, ()> {
        if let Some(addr) = relay_addr {
            self.add_address(relay, addr);
        }
        let relay_addr = self.dial_peer(&relay).await.map_err(|_| ())?;

        let mut swarm = self.swarm.lock().unwrap();
        let local_id = *swarm.local_peer_id();
        let relayed_addr = relay_addr
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(local_id.into()));
        let listener_id = swarm.listen_on(relayed_addr.clone()).map_err(|_| ())?;
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

    pub fn get_listeners(&self) -> Vec<&Listener> {
        self.listeners.values().collect()
    }

    pub fn stop_listening(&mut self) {
        let mut swarm = self.swarm.lock().unwrap();
        for (listener_id, _) in self.listeners.drain() {
            let _ = swarm.remove_listener(listener_id);
        }
    }

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

    pub async fn dial_peer(&self, peer: &PeerId) -> Result<Multiaddr, DialError> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.dial(peer)?;
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
                    address,
                    ..
                } if &peer_id == peer => return Err(DialError::InvalidAddress(address)),
                _ => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), event),
            }
        }
    }

    pub fn set_firewall_default(&self, direction: RuleDirection, default: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_firewall_default(direction, default)
    }

    pub fn get_firewall_default(&self) -> FirewallRules {
        let swarm = self.swarm.lock().unwrap();
        swarm.behaviour().get_firewall_default().clone()
    }

    pub fn remove_firewall_default(&self, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_firewall_default(direction)
    }

    pub fn get_peer_rules(&self, peer: &PeerId) -> Option<FirewallRules> {
        let swarm = self.swarm.lock().unwrap();
        swarm.behaviour().get_peer_rules(peer).cloned()
    }

    pub fn set_peer_rule(&self, peer: PeerId, direction: RuleDirection, rule: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_peer_rule(peer, direction, rule)
    }

    pub fn remove_peer_rule(&self, peer: PeerId, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_peer_rule(peer, direction)
    }

    pub fn get_addrs(&self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().addresses_of_peer(peer)
    }

    pub fn add_address(&self, peer: PeerId, address: Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_address(peer, address)
    }

    pub fn remove_address(&self, peer: &PeerId, address: &Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_address(peer, address)
    }

    pub fn get_relay_addr(&self, relay: &PeerId) -> Option<Multiaddr> {
        let swarm = self.swarm.lock().unwrap();
        swarm.behaviour().get_relay_addr(relay)
    }

    pub fn add_dialing_relay(&self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_dialing_relay(peer, address)
    }

    pub fn remove_dialing_relay(&self, peer: &PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_dialing_relay(peer)
    }

    pub fn set_dialing_not_use_relay(&self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_not_use_relay(peer)
    }

    pub fn set_dialing_use_relay(&self, peer: PeerId, relay: PeerId) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_use_relay(peer, relay)
    }

    pub fn ban_peer(&self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.ban_peer_id(peer);
    }

    pub fn unban_peer(&self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.unban_peer_id(peer);
    }

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

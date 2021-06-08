// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// mod swarm;
use crate::{
    behaviour::{assemble_relayed_addr, BehaviourEvent, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallRequest, FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    Keypair, NetworkEvents, ReceiveRequest, ResponseReceiver, RqRsMessage,
};
use async_std::task::{self, Context};
use futures::{channel::mpsc::Sender, future::poll_fn, FutureExt};
use libp2p::{
    core::{connection::ListenerId, transport::Transport, upgrade, Multiaddr, PeerId},
    mdns::{Mdns, MdnsConfig},
    noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{DialError, Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Debug,
    sync::{Arc, Mutex},
    thread,
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
        let mdns = Mdns::new(MdnsConfig::default())
            .await
            .expect("Failed to create mdns behaviour.");
        let behaviour = NetBehaviour::new(config, mdns, relay_behaviour, ask_firewall_chan);
        let swarm = Swarm::new(transport, behaviour, peer);

        let swarm_rw_lock = Arc::new(Mutex::new(swarm));
        let rw_lock_clone = Arc::clone(&swarm_rw_lock);
        let inbound_req_chan_clone = inbound_req_chan.clone();
        let net_events_chan_clone = net_events_chan.clone();

        thread::spawn(move || Self::run(rw_lock_clone, inbound_req_chan_clone, net_events_chan_clone));

        ShCommunication {
            swarm: swarm_rw_lock,
            listeners: HashMap::new(),
            request_chan: inbound_req_chan,
            net_events_chan,
        }
    }

    // pub async fn shutdown(mut self) {
    // self.task_handle.cancel().await;
    // self.request_chan.close_channel();
    // }

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
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) => {
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    return Ok(addr);
                }
                other => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), other),
            }
        }
    }

    pub async fn start_relayed_listening(&mut self, relay: PeerId) -> Result<Multiaddr, ()> {
        let mut swarm = self.swarm.lock().unwrap();
        let local_id = *swarm.local_peer_id();
        let relay_addr = swarm.behaviour_mut().get_relay_addr(&relay).ok_or(())?;
        let relayed_addr = assemble_relayed_addr(local_id, relay, relay_addr);
        let listener_id = swarm.listen_on(relayed_addr.clone()).map_err(|_| ())?;
        if !swarm.is_connected(&relay) {
            loop {
                match swarm.next_event().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay => break,
                    SwarmEvent::UnreachableAddr { peer_id, .. } if peer_id == relay => return Err(()),
                    other => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), other),
                }
            }
        }
        loop {
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) if addr == relayed_addr => {
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    return Ok(addr);
                }
                other => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), other),
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

    pub async fn dial_peer(&self, peer: &PeerId) -> Result<(), DialError> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.dial(peer)?;
        loop {
            match swarm.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if &peer_id == peer => return Ok(()),
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    attempts_remaining: 0,
                    address,
                    ..
                } if &peer_id == peer => return Err(DialError::InvalidAddress(address)),
                other => Self::handle_swarm_event(self.request_chan.clone(), self.net_events_chan.clone(), other),
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
    ) {
        loop {
            if let Ok(mut swarm) = swarm_mutex.lock() {
                if let Some(event) = swarm.next_event().now_or_never() {
                    Self::handle_swarm_event(request_channel.clone(), net_events_chan.clone(), event);
                }
            }
        }
    }
}

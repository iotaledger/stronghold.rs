// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// mod swarm;
use crate::{
    behaviour::{assemble_relayed_addr, NetBehaviour, NetBehaviourConfig},
    firewall::{FirewallRequest, FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    libp2p::Keypair,
    BehaviourEvent, RequestMessage, ResponseReceiver, RqRsMessage,
};
use async_std::{
    future::poll_fn,
    task::{self, Context, JoinHandle, Poll},
};
use futures::{channel::mpsc::Sender, StreamExt};
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
    sync::{Arc, Mutex},
};

pub struct Listener {
    addrs: SmallVec<[Multiaddr; 6]>,
    uses_relay: Option<PeerId>,
}

pub struct ShCommunication<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    task_handle: JoinHandle<()>,
    swarm: Arc<Mutex<Swarm<NetBehaviour<Rq, Rs, P>>>>,
    listeners: HashMap<ListenerId, Listener>,
    request_chan: Sender<RequestMessage<Rq, Rs>>,
}

impl<Rq, Rs, P> ShCommunication<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    pub async fn new(
        keypair: Keypair,
        config: NetBehaviourConfig,
        ask_firewall_chan: Sender<FirewallRequest<P>>,
        inbound_req_chan: Sender<RequestMessage<Rq, Rs>>,
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

        let swarm_mutex = Arc::new(Mutex::new(swarm));
        let task_handle = task::spawn(Self::run(Arc::clone(&swarm_mutex), inbound_req_chan.clone()));

        ShCommunication {
            task_handle,
            swarm: swarm_mutex,
            listeners: HashMap::new(),
            request_chan: inbound_req_chan,
        }
    }

    pub async fn shutdown(mut self) {
        self.task_handle.cancel().await;
        self.request_chan.close_channel();
    }

    pub fn get_peer_id(&mut self) -> PeerId {
        let swarm = self.swarm.lock().unwrap();
        *swarm.local_peer_id()
    }

    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().send_request(peer, request)
    }

    pub async fn start_listening(&mut self, address: Option<Multiaddr>) -> Result<Multiaddr, ()> {
        let mut swarm = self.swarm.lock().unwrap();
        let a = address.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."));
        let listener_id = swarm.listen_on(a).map_err(|_| ())?;
        loop {
            match swarm.next_event().await {
                SwarmEvent::Behaviour(event) => {
                    let req_chanel = self.request_chan.clone();
                    Self::handle_behavior_event(req_chanel, event);
                }
                SwarmEvent::NewListenAddr(addr) => {
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    return Ok(addr);
                }
                _ => {}
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
                    SwarmEvent::Behaviour(event) => {
                        let req_chanel = self.request_chan.clone();
                        Self::handle_behavior_event(req_chanel, event);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay => break,
                    SwarmEvent::UnreachableAddr { peer_id, .. } if peer_id == relay => return Err(()),
                    _ => {}
                }
            }
        }
        loop {
            match swarm.next_event().await {
                SwarmEvent::Behaviour(event) => {
                    let req_chanel = self.request_chan.clone();
                    Self::handle_behavior_event(req_chanel, event);
                }
                SwarmEvent::NewListenAddr(addr) if addr == relayed_addr => {
                    let listener = Listener {
                        addrs: smallvec![addr.clone()],
                        uses_relay: None,
                    };
                    self.listeners.insert(listener_id, listener);
                    return Ok(addr);
                }
                _ => {}
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

    pub async fn dial_peer(&mut self, peer: &PeerId) -> Result<(), DialError> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.dial(peer)?;
        loop {
            match swarm.next_event().await {
                SwarmEvent::Behaviour(event) => {
                    let req_chanel = self.request_chan.clone();
                    Self::handle_behavior_event(req_chanel, event);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } if &peer_id == peer => return Ok(()),
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    attempts_remaining: 0,
                    address,
                    ..
                } if &peer_id == peer => return Err(DialError::InvalidAddress(address)),
                _ => {}
            }
        }
    }

    pub fn set_firewall_default(&mut self, direction: RuleDirection, default: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_firewall_default(direction, default)
    }

    pub fn get_firewall_default(&mut self) -> FirewallRules {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().get_firewall_default().clone()
    }

    pub fn remove_firewall_default(&mut self, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_firewall_default(direction)
    }

    pub fn get_peer_rules(&mut self, peer: &PeerId) -> Option<FirewallRules> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().get_peer_rules(peer).cloned()
    }

    pub fn set_peer_rule(&mut self, peer: PeerId, direction: RuleDirection, rule: Rule) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_peer_rule(peer, direction, rule)
    }

    pub fn remove_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_peer_rule(peer, direction)
    }

    pub fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_address(peer, address)
    }

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_address(peer, address)
    }

    pub fn get_relay_addr(&self, relay: &PeerId) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().get_relay_addr(relay)
    }

    pub fn add_dialing_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().add_dialing_relay(peer, address)
    }

    pub fn remove_dialing_relay(&mut self, peer: &PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().remove_dialing_relay(peer)
    }

    pub fn set_dialing_not_use_relay(&mut self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_not_use_relay(peer)
    }

    pub fn set_dialing_use_relay(&mut self, peer: PeerId, relay: PeerId) -> Option<Multiaddr> {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.behaviour_mut().set_use_relay(peer, relay)
    }

    pub fn ban_peer(&mut self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.ban_peer_id(peer);
    }

    pub fn unban_peer(&mut self, peer: PeerId) {
        let mut swarm = self.swarm.lock().unwrap();
        swarm.unban_peer_id(peer);
    }

    fn handle_behavior_event(mut request_channel: Sender<RequestMessage<Rq, Rs>>, event: BehaviourEvent<Rq, Rs>) {
        if let BehaviourEvent::ReceiveRequest { request, .. } = event {
            task::spawn(async move {
                let _ = poll_fn(|cx: &mut Context| request_channel.poll_ready(cx)).await;
                let _ = request_channel.start_send(request);
            });
        }
    }

    async fn run(
        swarm_mutex: Arc<Mutex<Swarm<NetBehaviour<Rq, Rs, P>>>>,
        request_channel: Sender<RequestMessage<Rq, Rs>>,
    ) {
        poll_fn(move |cx: &mut Context| {
            let mut swarm = swarm_mutex.lock().unwrap();
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    let req_chanel = request_channel.clone();
                    Self::handle_behavior_event(req_chanel, event);
                }
                Poll::Ready(None) => return Poll::Ready(()),
                _ => {}
            }
            Poll::Pending
        })
        .await
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{ask::ask, message::*};
use crate::behaviour::{
    message::{P2PEvent, P2PReqResEvent},
    MessageEvent, P2PNetworkBehaviour,
};
use core::{marker::PhantomData, ops::Deref, time::Duration};
use futures::{channel::mpsc::UnboundedReceiver, prelude::*, select};
use libp2p::{
    core::{connection::ListenerId, multiaddr::Protocol, ConnectedPoint},
    identity::Keypair,
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use riker::{actors::*, Message};
use std::{collections::HashMap, fmt::Debug, string::ToString, time::Instant};

#[derive(Clone, Debug)]
struct ClientPeers<T: MessageEvent, V: Message + From<T>> {
    client_ref: ActorRef<V>,
    listener_id: ListenerId,
    peers: Vec<PeerId>,
    marker: PhantomData<T>,
}

impl<T: MessageEvent, V: Message + From<T>> ClientPeers<T, V> {
    fn new(client_ref: ActorRef<V>, listener_id: ListenerId) -> Self {
        ClientPeers {
            client_ref,
            listener_id,
            peers: vec![],
            marker: PhantomData,
        }
    }

    fn client_ref(&self) -> ActorRef<V> {
        self.client_ref.clone()
    }

    fn listener_id(&self) -> ListenerId {
        self.listener_id
    }

    fn add_peer(&mut self, peer: PeerId) {
        self.peers.push(peer)
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        self.peers = self
            .peers
            .iter()
            .filter_map(|&p| if &p != peer { Some(p) } else { None })
            .collect();
    }

    fn contains_peer(&self, peer: &PeerId) -> bool {
        self.peers.contains(peer)
    }
}

struct ActorTargetMap<T: MessageEvent, V: Message + From<T>> {
    // map the requests to their sender
    request_sender_map: HashMap<String, Sender>,
    // map the remote peers to their targeted client
    client_port_map: HashMap<u16, ClientPeers<T, V>>,
    marker: PhantomData<T>,
}

impl<T: MessageEvent, V: Message + From<T>> ActorTargetMap<T, V> {
    fn new() -> Self {
        ActorTargetMap {
            request_sender_map: HashMap::new(),
            client_port_map: HashMap::new(),
            marker: PhantomData,
        }
    }
    fn insert_sender<K: ToString>(&mut self, key: K, sender: Sender) {
        self.request_sender_map.insert(key.to_string(), sender);
    }

    fn take_sender<K: ToString>(&mut self, key: K) -> Option<Sender> {
        self.request_sender_map.remove(&key.to_string())
    }

    fn add_client(&mut self, client_ref: ActorRef<V>, port: u16, listener_id: ListenerId) {
        self.client_port_map
            .insert(port, ClientPeers::new(client_ref, listener_id));
    }

    fn get_client_ref(&self, peer: &PeerId) -> Option<ActorRef<V>> {
        self.client_port_map
            .iter()
            .find(|(_, client_port_map)| client_port_map.contains_peer(peer))
            .map(|(_, client_port_map)| client_port_map.client_ref())
    }

    fn remove_endpoint(&mut self, client_ref: ActorRef<V>) -> Option<ListenerId> {
        let mut listener_id = None;
        self.client_port_map = self
            .client_port_map
            .iter()
            .filter(|(_, client_port_map)| {
                if client_port_map.client_ref() == client_ref {
                    listener_id = Some(client_port_map.listener_id());
                    false
                } else {
                    true
                }
            })
            .map(|(p, c)| (*p, c.clone()))
            .collect();
        listener_id
    }

    fn insert_peer(&mut self, port: u16, peer: PeerId) -> Option<ActorRef<V>> {
        // remove peer from existing map
        self.remove_peer(&peer);
        if let Some((_, client_port_map)) = self.client_port_map.iter_mut().find(|(&p, _)| p == port) {
            client_port_map.add_peer(peer);
            Some(client_port_map.client_ref())
        } else {
            None
        }
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        self.client_port_map = self
            .client_port_map
            .iter_mut()
            .map(|(p, client_port_map)| {
                client_port_map.remove_peer(peer);
                (*p, client_port_map.clone())
            })
            .collect();
    }
}

// Separate task that manages the swarm communication.
pub struct SwarmTask<T: MessageEvent, U: MessageEvent, V: From<T> + Message> {
    sys: ActorSystem,
    swarm: Swarm<P2PNetworkBehaviour<T, U>>,
    swarm_rx: UnboundedReceiver<(CommunicationRequest<T, V>, Sender)>,
    actor_map: ActorTargetMap<T, V>,
}

impl<T: MessageEvent, U: MessageEvent, V: From<T> + Message> SwarmTask<T, U, V> {
    pub fn new(
        keypair: Keypair,
        system: ActorSystem,
        swarm_rx: UnboundedReceiver<(CommunicationRequest<T, V>, Sender)>,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let swarm = P2PNetworkBehaviour::<T, U>::init_swarm(keypair).unwrap();
        SwarmTask {
            sys: system,
            swarm,
            swarm_rx,
            actor_map: ActorTargetMap::new(),
        }
    }

    // Poll from the swarm for events from remote peers, and from the `swarm_tx` channel for events from the local
    // actor, and forward them.
    pub async fn poll_swarm(mut self) {
        loop {
            select! {
                actor_event = self.swarm_rx.next().fuse() => {
                    if let Some((message, sender)) = actor_event {
                        self.handle_actor_request(message, sender).await
                    } else {
                        return
                    }
                },
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event).await,
            };
        }
    }

    // Handle the messages that are received from other actors in the system..
    async fn handle_actor_request(&mut self, event: CommunicationRequest<T, V>, sender: Sender) {
        match event {
            CommunicationRequest::RequestMsg { peer_id, request } => {
                let request_id = self.swarm.send_request(&peer_id, request);
                self.actor_map.insert_sender(request_id, sender);
            }
            CommunicationRequest::ConnectPeer { target, client_ref: _ } => {
                let res: Result<(), ConnectPeerError> = match target {
                    PeerTarget::Id(peer_id) => {
                        if let Err(error) = Swarm::dial(&mut self.swarm, &peer_id) {
                            Err(error.into())
                        } else {
                            self.actor_map.insert_sender(peer_id, sender.clone());
                            Ok(())
                        }
                    }
                    PeerTarget::Addr(addr) => {
                        if let Err(limit) = Swarm::dial_addr(&mut self.swarm, addr.clone()) {
                            Err(ConnectPeerError::ConnectionLimit(limit))
                        } else {
                            self.actor_map.insert_sender(addr, sender.clone());
                            Ok(())
                        }
                    }
                };
                if let Err(e) = res {
                    if let Some(sender) = sender {
                        let result = CommunicationResults::<U>::ConnectPeerResult(Err(e));
                        sender.try_tell(result, None).unwrap();
                    }
                }
            }
            CommunicationRequest::CheckConnection(peer_id) => {
                if let Some(sender) = sender {
                    let result =
                        CommunicationResults::<U>::CheckConnectionResult(Swarm::is_connected(&self.swarm, &peer_id));
                    sender.try_tell(result, None).unwrap();
                }
            }
            CommunicationRequest::GetSwarmInfo => {
                if let Some(sender) = sender {
                    let peer_id = *Swarm::local_peer_id(&self.swarm);
                    let listeners = Swarm::listeners(&self.swarm).cloned().collect();
                    let swarm_info = CommunicationResults::<U>::SwarmInfo { peer_id, listeners };
                    sender.try_tell(swarm_info, None).unwrap();
                }
            }
            CommunicationRequest::StartListening { client_ref, addr } => {
                self.start_listening(client_ref, addr, sender).await
            }
            CommunicationRequest::RemoveListener(client_ref) => {
                let listener_id = self.actor_map.remove_endpoint(client_ref);
                let res = if let Some(listener_id) = listener_id {
                    Swarm::remove_listener(&mut self.swarm, listener_id)
                } else {
                    Err(())
                };
                let res = CommunicationResults::<U>::RemoveListenerResult(res);
                sender.unwrap().try_tell(res, None).unwrap();
            }
            CommunicationRequest::BanPeer(peer_id) => {
                Swarm::ban_peer_id(&mut self.swarm, peer_id);
                let res = CommunicationResults::<U>::BannedPeer(peer_id);
                sender.unwrap().try_tell(res, None).unwrap();
            }
            CommunicationRequest::UnbanPeer(peer_id) => {
                Swarm::unban_peer_id(&mut self.swarm, peer_id);
                let res = CommunicationResults::<U>::UnbannedPeer(peer_id);
                sender.unwrap().try_tell(res, None).unwrap();
            }
        }
    }

    async fn start_listening(&mut self, client_ref: ActorRef<V>, addr: Option<Multiaddr>, sender: Sender) {
        let addr = addr.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        if let Ok(listener_id) = Swarm::listen_on(&mut self.swarm, addr) {
            let start = Instant::now();
            loop {
                match self.swarm.next_event().await {
                    SwarmEvent::NewListenAddr(addr) => {
                        if let Some(Protocol::Tcp(port)) = addr.clone().pop() {
                            self.actor_map.add_client(client_ref, port, listener_id);
                            let res = CommunicationResults::<U>::StartListeningResult(Ok(addr));
                            sender.unwrap().try_tell(res, None).unwrap();
                            break;
                        }
                    }
                    other => self.handle_swarm_event(other).await,
                }
                if start.elapsed() > Duration::new(5, 0) {
                    let res = CommunicationResults::<U>::StartListeningResult(Err(()));
                    sender.unwrap().try_tell(res, None).unwrap();
                    break;
                }
            }
        } else {
            let res = CommunicationResults::<U>::StartListeningResult(Err(()));
            sender.unwrap().try_tell(res, None).unwrap();
        }
    }

    // Poll from the swarm for requests and responses from remote peers, and publish them in the channel.
    async fn handle_swarm_event<HandleErr>(&mut self, event: SwarmEvent<P2PEvent<T, U>, HandleErr>) {
        match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => match boxed_event.deref().clone() {
                P2PReqResEvent::Req {
                    peer_id,
                    request_id,
                    request,
                } => {
                    if let Some(client_ref) = self.actor_map.get_client_ref(&peer_id) {
                        let res: U = ask(&self.sys, &client_ref, V::from(request)).await;
                        self.swarm.send_response(res, request_id).unwrap();
                    }
                }
                P2PReqResEvent::Res {
                    peer_id: _,
                    request_id,
                    response,
                } => {
                    if let Some(Some(actor_ref)) = self.actor_map.take_sender(&request_id) {
                        actor_ref
                            .try_tell(CommunicationResults::RequestMsgResult(Ok(response)), None)
                            .unwrap();
                    }
                }
                P2PReqResEvent::InboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.actor_map.take_sender(&request_id) {
                        let msg = CommunicationResults::<U>::RequestMsgResult(Err(RequestMessageError::Inbound(error)));
                        actor_ref.try_tell(msg, None).unwrap();
                    }
                }
                P2PReqResEvent::OutboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.actor_map.take_sender(&request_id) {
                        let msg =
                            CommunicationResults::<U>::RequestMsgResult(Err(RequestMessageError::Outbound(error)));
                        actor_ref.try_tell(msg, None).unwrap();
                    }
                }
                _ => {}
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established: _,
            } => match endpoint {
                ConnectedPoint::Dialer { address } => {
                    let actor_ref = if let Some(actor) = self.actor_map.take_sender(peer_id) {
                        actor
                    } else if let Some(actor) = self.actor_map.take_sender(address) {
                        actor
                    } else {
                        None
                    };
                    if let Some(actor_ref) = actor_ref {
                        let msg = CommunicationResults::<U>::ConnectPeerResult(Ok(peer_id));
                        actor_ref.try_tell(msg, None).unwrap();
                    }
                }
                ConnectedPoint::Listener {
                    mut local_addr,
                    send_back_addr: _,
                } => {
                    if let Some(Protocol::Tcp(port)) = local_addr.pop() {
                        self.actor_map.insert_peer(port, peer_id);
                    }
                }
            },
            SwarmEvent::UnreachableAddr {
                peer_id,
                address,
                error,
                attempts_remaining: 0,
            } => {
                let actor_ref = if let Some(actor) = self.actor_map.take_sender(peer_id) {
                    actor
                } else if let Some(actor) = self.actor_map.take_sender(address) {
                    actor
                } else {
                    None
                };
                if let Some(actor_ref) = actor_ref {
                    let msg = CommunicationResults::<U>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    actor_ref.try_tell(msg, None).unwrap();
                }
            }
            SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                if let Some(Some(actor_ref)) = self.actor_map.take_sender(address) {
                    let msg = CommunicationResults::<U>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    actor_ref.try_tell(msg, None).unwrap();
                }
            }
            _ => {}
        }
    }
}

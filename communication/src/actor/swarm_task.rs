// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{ask::ask, message::*, CommunicationConfig};
use crate::behaviour::{
    message::{P2PEvent, P2PReqResEvent},
    MessageEvent, P2PNetworkBehaviour,
};
use core::{ops::Deref, time::Duration};
use futures::{channel::mpsc::UnboundedReceiver, future, prelude::*, select};
use libp2p::{
    core::{connection::ListenerId, ConnectedPoint},
    identity::Keypair,
    swarm::{DialError, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use riker::{actors::*, Message};
use std::{
    task::{Context, Poll},
    time::Instant,
};

// Separate task that manages the swarm communication.
pub struct SwarmTask<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    config: CommunicationConfig<Req, T, U>,
    swarm: Swarm<P2PNetworkBehaviour<Req, Res>>,
    swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, T>, Sender)>,
    listener: Option<ListenerId>,
}

impl<Req, Res, T, U> SwarmTask<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    pub fn new(
        keypair: Keypair,
        config: CommunicationConfig<Req, T, U>,
        swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, T>, Sender)>,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let swarm = P2PNetworkBehaviour::<Req, Res>::init_swarm(keypair).unwrap();
        SwarmTask {
            config,
            swarm,
            swarm_rx,
            listener: None,
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

    fn send_response(result: CommunicationResults<Res>, sender: Sender) {
        if let Some(sender) = sender {
            sender.try_tell(result, None).unwrap();
        }
    }

    // Handle the messages that are received from other actors in the system..
    async fn handle_actor_request(&mut self, event: CommunicationRequest<Req, T>, sender: Sender) {
        match event {
            CommunicationRequest::RequestMsg { peer_id, request } => {
                let res = self.send_request(peer_id, request).await;
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::SetClientRef(client_ref) => {
                self.config.client = client_ref;
                let res = CommunicationResults::SetClientRefResult;
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::ConnectPeer { peer_id, addr } => {
                let res = self.connect_peer(peer_id, addr).await;
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::CheckConnection(peer_id) => {
                let is_connected = Swarm::is_connected(&self.swarm, &peer_id);
                let res = CommunicationResults::CheckConnectionResult(is_connected);
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::GetSwarmInfo => {
                let peer_id = *Swarm::local_peer_id(&self.swarm);
                let listeners = Swarm::listeners(&self.swarm).cloned().collect();
                let res = CommunicationResults::<Res>::SwarmInfo { peer_id, listeners };
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::StartListening(addr) => {
                let res = self.start_listening(addr).await;
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::RemoveListener => {
                let result = if let Some(listener_id) = self.listener.take() {
                    Swarm::remove_listener(&mut self.swarm, listener_id)
                } else {
                    Err(())
                };
                let res = CommunicationResults::<Res>::RemoveListenerResult(result);
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::BanPeer(peer_id) => {
                Swarm::ban_peer_id(&mut self.swarm, peer_id);
                let res = CommunicationResults::<Res>::BannedPeer(peer_id);
                sender.unwrap().try_tell(res, None).unwrap();
            }
            CommunicationRequest::UnbanPeer(peer_id) => {
                Swarm::unban_peer_id(&mut self.swarm, peer_id);
                let res = CommunicationResults::<Res>::UnbannedPeer(peer_id);
                sender.unwrap().try_tell(res, None).unwrap();
            }
        }
    }

    async fn ask_permission(&mut self, request: Req, remote: PeerId, direction: RequestDirection) -> FirewallResponse {
        let start = Instant::now();
        let firewall_request = FirewallRequest::new(request, remote, direction);
        let mut ask_permission = ask(&self.config.system, &self.config.firewall, firewall_request);
        future::poll_fn(move |cx: &mut Context<'_>| match ask_permission.poll_unpin(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                if start.elapsed() > Duration::new(3, 0) {
                    Poll::Ready(FirewallResponse::Drop)
                } else {
                    Poll::Pending
                }
            }
        })
        .await
    }

    async fn start_listening(&mut self, addr: Option<Multiaddr>) -> CommunicationResults<Res> {
        let addr = addr.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        if let Ok(listener_id) = Swarm::listen_on(&mut self.swarm, addr) {
            let start = Instant::now();
            loop {
                match self.swarm.next_event().await {
                    SwarmEvent::NewListenAddr(addr) => {
                        self.listener = Some(listener_id);
                        return CommunicationResults::<Res>::StartListeningResult(Ok(addr));
                    }
                    other => self.handle_swarm_event(other).await,
                }
                if start.elapsed() > Duration::new(5, 0) {
                    return CommunicationResults::<Res>::StartListeningResult(Err(()));
                }
            }
        } else {
            return CommunicationResults::<Res>::StartListeningResult(Err(()));
        }
    }

    async fn connect_peer(&mut self, target_peer: PeerId, target_addr: Multiaddr) -> CommunicationResults<Res> {
        if let Err(err) = Swarm::dial(&mut self.swarm, &target_peer) {
            match err {
                DialError::NoAddresses => {
                    if let Err(limit) = Swarm::dial_addr(&mut self.swarm, target_addr.clone()) {
                        return CommunicationResults::<Res>::ConnectPeerResult(Err(ConnectPeerError::ConnectionLimit(
                            limit,
                        )));
                    }
                }
                _ => {
                    return CommunicationResults::<Res>::ConnectPeerResult(Err(err.into()));
                }
            }
        }
        loop {
            let event = self.swarm.next_event().await;
            match event {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: ConnectedPoint::Dialer { address: _ },
                    num_established: _,
                } => {
                    if peer_id == target_peer {
                        return CommunicationResults::<Res>::ConnectPeerResult(Ok(peer_id));
                    } else {
                        self.handle_swarm_event(event).await
                    }
                }
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    address: _,
                    error,
                    attempts_remaining: 0,
                } => {
                    if peer_id == target_peer {
                        return CommunicationResults::<Res>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    if address == target_addr {
                        return CommunicationResults::<Res>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    }
                }
                _ => self.handle_swarm_event(event).await,
            }
        }
    }

    async fn send_request(&mut self, peer_id: PeerId, request: Req) -> CommunicationResults<Res> {
        let permission = self
            .ask_permission(request.clone(), peer_id, RequestDirection::Out)
            .await;
        match permission {
            FirewallResponse::Accept => {
                let req_id = self.swarm.send_request(&peer_id, request);
                loop {
                    let event = self.swarm.next_event().await;
                    match event {
                        SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                            match boxed_event.clone().deref().clone() {
                                P2PReqResEvent::Res {
                                    peer_id: _,
                                    request_id,
                                    response,
                                } => {
                                    if request_id == req_id {
                                        return CommunicationResults::RequestMsgResult(Ok(response));
                                    }
                                }
                                P2PReqResEvent::InboundFailure {
                                    peer_id: _,
                                    request_id,
                                    error,
                                } => {
                                    if request_id == req_id {
                                        let err = RequestMessageError::Inbound(error);
                                        return CommunicationResults::<Res>::RequestMsgResult(Err(err));
                                    }
                                }
                                P2PReqResEvent::OutboundFailure {
                                    peer_id: _,
                                    request_id,
                                    error,
                                } => {
                                    if request_id == req_id {
                                        let err = RequestMessageError::Outbound(error);
                                        return CommunicationResults::<Res>::RequestMsgResult(Err(err));
                                    }
                                }
                                P2PReqResEvent::Req {
                                    peer_id: _,
                                    request_id,
                                    request,
                                } => {
                                    let res: Res = ask(&self.config.system, &self.config.client, request).await;
                                    self.swarm.send_response(res, request_id).unwrap();
                                }
                                _ => {}
                            }
                        }
                        _ => self.handle_swarm_event(event).await,
                    }
                }
            }
            _ => return CommunicationResults::Rejected,
        }
    }

    // Poll from the swarm for requests and responses from remote peers, and publish them in the channel.
    async fn handle_swarm_event<HandleErr>(&mut self, event: SwarmEvent<P2PEvent<Req, Res>, HandleErr>) {
        match event {
            SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                P2PEvent::RequestResponse(boxed_event) => {
                    if let P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request,
                    } = boxed_event.deref().clone()
                    {
                        let permission = self
                            .ask_permission(request.clone(), peer_id, RequestDirection::In)
                            .await;
                        if let FirewallResponse::Accept = permission {
                            let res: Res = ask(&self.config.system, &self.config.client, request).await;
                            self.swarm.send_response(res, request_id).unwrap();
                        }
                    }
                }
                P2PEvent::Identify(identify_event) => {
                    let _swarm_event = CommunicationSwarmEvent::Identify(identify_event);
                }
                P2PEvent::Mdns(mdns_event) => {
                    let _swarm_event = CommunicationSwarmEvent::Mdns(mdns_event);
                }
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint:
                    ConnectedPoint::Listener {
                        local_addr,
                        send_back_addr,
                    },
                num_established,
            } => {
                let _swarm_event = CommunicationSwarmEvent::IncomingConnectionEstablished {
                    peer_id,
                    local_addr,
                    send_back_addr,
                    num_established,
                };
            }
            _ => {}
        }
    }
}

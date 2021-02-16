// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::behaviour::{
    MessageEvent, P2PEvent, P2PNetworkBehaviour, P2POutboundFailure, P2PReqResEvent, RequestEnvelope,
};
use core::{ops::Deref, str::FromStr, time::Duration};
use futures::{channel::mpsc::UnboundedReceiver, future, prelude::*, select};
use libp2p::{
    core::{connection::ListenerId, ConnectedPoint},
    identity::Keypair,
    request_response::RequestId,
    swarm::{DialError, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use riker::{actors::*, Message};
use std::{
    task::{Context, Poll},
    time::Instant,
};

// Separate task that manages the swarm communication.
pub(super) struct SwarmTask<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    system: ActorSystem,
    config: CommunicationConfig<Req, T, U>,
    swarm: Swarm<P2PNetworkBehaviour<RequestEnvelope<Req>, Res>>,
    swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, T>, Sender)>,
    listener: Option<ListenerId>,
    relay: RelayConfig,
}

impl<Req, Res, T, U> SwarmTask<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    pub fn new(
        system: ActorSystem,
        keypair: Keypair,
        config: CommunicationConfig<Req, T, U>,
        behaviour: BehaviourConfig,
        swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, T>, Sender)>,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let swarm = P2PNetworkBehaviour::<RequestEnvelope<Req>, Res>::init_swarm(keypair, behaviour).unwrap();
        SwarmTask {
            system,
            config,
            swarm,
            swarm_rx,
            listener: None,
            relay: RelayConfig::NoRelay,
        }
    }

    // Poll from the swarm for events from remote peers, and from the `swarm_tx` channel for events from the local
    // actor, and forward them.
    pub async fn poll_swarm(mut self) {
        loop {
            select! {
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event).await,
                actor_event = self.swarm_rx.next().fuse() => {
                    if let Some((message, sender)) = actor_event {
                        if let CommunicationRequest::Shutdown = message {
                            break;
                        } else {
                            self.handle_actor_request(message, sender).await
                        }
                    } else {
                        break
                    }
                },
            };
        }
        self.shutdown();
    }

    fn shutdown(mut self) {
        if let Some(listener_id) = self.listener.take() {
            let _ = Swarm::remove_listener(&mut self.swarm, listener_id);
        }
        self.swarm_rx.close();
    }

    async fn handle_incoming_envelope(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        request: RequestEnvelope<Req>,
    ) {
        if Swarm::local_peer_id(&self.swarm).to_string() != request.target {
            return;
        }
        if let Ok(source) = PeerId::from_str(&request.source) {
            // validate that peer is either directly connected or the request was forwarded from the relay
            if peer_id == source
                || match self.relay {
                    RelayConfig::RelayAlways(relay_id) | RelayConfig::RelayBackup(relay_id) => peer_id == relay_id,
                    RelayConfig::NoRelay => false,
                }
            {
                let permission = self
                    .ask_permission(request.message.clone(), source, RequestDirection::In)
                    .await;
                if let FirewallResponse::Accept = permission {
                    let res: Res = ask(&self.system, &self.config.client, request.message).await;
                    self.swarm.send_response(request_id, res).unwrap();
                }
            }
        }
    }

    // Send incoming request to the client.
    // Eventually other swarm events lik e.g. incoming connection should also be send to some top level actor.
    async fn handle_swarm_event<HandleErr>(
        &mut self,
        event: SwarmEvent<P2PEvent<RequestEnvelope<Req>, Res>, HandleErr>,
    ) {
        match event {
            SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                P2PEvent::RequestResponse(boxed_event) => {
                    if let P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request,
                    } = boxed_event.deref().clone()
                    {
                        self.handle_incoming_envelope(peer_id, request_id, request).await;
                    }
                }
                P2PEvent::Identify(_) | P2PEvent::Mdns(_) => {}
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
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address: _ },
                num_established: 0,
                cause: None,
            } => {
                // reestablish timedout connection to relay
                match &self.relay {
                    RelayConfig::RelayAlways(relay_id) | RelayConfig::RelayBackup(relay_id) => {
                        if peer_id == *relay_id {
                            let _ = Swarm::dial(&mut self.swarm, &peer_id);
                        }
                    }
                    RelayConfig::NoRelay => {}
                }
            }
            _ => {}
        }
    }

    // Ask the firewall actor for FirewallResponse, return FirewallResponse::Drop on timeout
    async fn ask_permission(&mut self, request: Req, remote: PeerId, direction: RequestDirection) -> FirewallResponse {
        let start = Instant::now();
        let firewall_request = FirewallRequest::new(request, remote, direction);
        let mut ask_permission = ask(&self.system, &self.config.firewall, firewall_request);
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

    // Handle the messages that are received from other actors in the system..
    async fn handle_actor_request(&mut self, event: CommunicationRequest<Req, T>, sender: Sender) {
        match event {
            CommunicationRequest::RequestMsg { peer_id, request } => {
                let res = if let FirewallResponse::Accept = self
                    .ask_permission(request.clone(), peer_id, RequestDirection::Out)
                    .await
                {
                    let local_peer = Swarm::local_peer_id(&self.swarm);
                    let envelope = RequestEnvelope {
                        source: local_peer.to_string(),
                        message: request,
                        target: peer_id.to_string(),
                    };
                    match self.relay {
                        RelayConfig::NoRelay => self.send_request(peer_id, envelope).await,
                        RelayConfig::RelayAlways(relay_id) => self.send_request(relay_id, envelope).await,
                        RelayConfig::RelayBackup(relay_id) => {
                            // try sending directly, otherwise use relay
                            let res = self.send_request(peer_id, envelope.clone()).await;
                            if let CommunicationResults::RequestMsgResult(Err(RequestMessageError::Outbound(
                                P2POutboundFailure::DialFailure,
                            ))) = res
                            {
                                self.send_request(relay_id, envelope).await
                            } else {
                                res
                            }
                        }
                    }
                } else {
                    CommunicationResults::RequestMsgResult(Err(RequestMessageError::Rejected(FirewallBlocked::Local)))
                };
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
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::UnbanPeer(peer_id) => {
                Swarm::unban_peer_id(&mut self.swarm, peer_id);
                let res = CommunicationResults::<Res>::UnbannedPeer(peer_id);
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::SetRelay(config) => {
                self.relay = config;
                let res = CommunicationResults::<Res>::SetRelay;
                SwarmTask::<Req, Res, T, U>::send_response(res, sender);
            }
            CommunicationRequest::Shutdown => unreachable!(),
        }
    }

    // Send a reponse to the sender of a previous [`CommunicationRequest`]
    fn send_response(result: CommunicationResults<Res>, sender: Sender) {
        if let Some(sender) = sender {
            let _ = sender.try_tell(result, None);
        }
    }

    // Start listening on the swarm, if not address is provided, the port will be OS assigned.
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
                if start.elapsed() > Duration::new(10, 0) {
                    return CommunicationResults::<Res>::StartListeningResult(Err(()));
                }
            }
        } else {
            return CommunicationResults::<Res>::StartListeningResult(Err(()));
        }
    }

    // Try to connect a remote peer by id or address.
    async fn connect_peer(&mut self, target_peer: PeerId, target_addr: Multiaddr) -> CommunicationResults<Res> {
        if let Err(err) = Swarm::dial(&mut self.swarm, &target_peer) {
            match err {
                DialError::NoAddresses => {
                    if let Err(limit) = Swarm::dial_addr(&mut self.swarm, target_addr.clone()) {
                        return CommunicationResults::ConnectPeerResult(Err(ConnectPeerError::ConnectionLimit(limit)));
                    }
                }
                _ => {
                    return CommunicationResults::ConnectPeerResult(Err(err.into()));
                }
            }
        }
        let start = Instant::now();
        loop {
            let event = self.swarm.next_event().await;
            match event {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: ConnectedPoint::Dialer { address: _ },
                    num_established: _,
                } => {
                    if peer_id == target_peer {
                        return CommunicationResults::ConnectPeerResult(Ok(peer_id));
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
                        return CommunicationResults::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    if address == target_addr {
                        return CommunicationResults::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    }
                }
                _ => self.handle_swarm_event(event).await,
            }
            if start.elapsed() > Duration::new(3, 0) {
                return CommunicationResults::ConnectPeerResult(Err(ConnectPeerError::Timeout));
            }
        }
    }

    // Try sending a request to a remote peer if it was approved by the firewall, and return the received Response.
    // If no reponse is received, a RequestMessageError::Rejected will be returned.
    async fn send_request(&mut self, peer_id: PeerId, envelope: RequestEnvelope<Req>) -> CommunicationResults<Res> {
        let req_id = self.swarm.send_request(&peer_id, envelope);
        let start = Instant::now();
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
                                return CommunicationResults::RequestMsgResult(Err(err));
                            }
                        }
                        P2PReqResEvent::OutboundFailure {
                            peer_id: _,
                            request_id,
                            error,
                        } => {
                            if request_id == req_id {
                                let err = RequestMessageError::Outbound(error);
                                return CommunicationResults::RequestMsgResult(Err(err));
                            }
                        }
                        P2PReqResEvent::Req {
                            peer_id,
                            request_id,
                            request,
                        } => {
                            self.handle_incoming_envelope(peer_id, request_id, request).await;
                        }
                        _ => {}
                    }
                }
                _ => self.handle_swarm_event(event).await,
            }
            if start.elapsed() > Duration::new(10, 0) {
                return CommunicationResults::RequestMsgResult(Err(RequestMessageError::Rejected(
                    FirewallBlocked::Remote,
                )));
            }
        }
    }
}

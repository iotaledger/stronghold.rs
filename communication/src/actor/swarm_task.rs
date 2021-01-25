// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{
    message::{CommunicationResults, ConnectPeerError, RequestMessageError},
    *,
};
use crate::behaviour::{
    message::{P2PEvent, P2PReqResEvent},
    MessageEvent, P2PNetworkBehaviour,
};
use core::ops::Deref;
use futures::{channel::mpsc::UnboundedReceiver, prelude::*, select};
use libp2p::{
    core::ConnectedPoint,
    swarm::{Swarm, SwarmEvent},
};
use riker::actors::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, string::ToString};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "T: MessageEvent")]
struct RequestMessage<T: MessageEvent> {
    req: T,
    client_str: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "T: MessageEvent")]
struct ResponseMessage<T: MessageEvent>(Result<T, String>);

struct SenderMap {
    map: HashMap<String, Sender>,
}

impl SenderMap {
    fn new() -> Self {
        SenderMap { map: HashMap::new() }
    }
    fn insert<T: ToString>(&mut self, key: T, sender: Sender) {
        self.map.insert(key.to_string(), sender);
    }

    fn take<T: ToString>(&mut self, key: T) -> Option<Sender> {
        self.map.remove(&key.to_string())
    }
}

// Separate task that manages the swarm communication.
pub struct SwarmTask<T: MessageEvent, U: MessageEvent> {
    sys: ActorSystem,
    swarm: Swarm<P2PNetworkBehaviour<RequestMessage<T>, ResponseMessage<U>>>,
    swarm_rx: UnboundedReceiver<(CommunicationRequest<T>, Sender)>,
    sender_map: SenderMap,
}

impl<T: MessageEvent, U: MessageEvent> SwarmTask<T, U> {
    pub fn new(
        keypair: Keypair,
        system: ActorSystem,
        swarm_rx: UnboundedReceiver<(CommunicationRequest<T>, Sender)>,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let swarm = P2PNetworkBehaviour::<RequestMessage<T>, ResponseMessage<U>>::init_swarm(keypair).unwrap();
        SwarmTask {
            sys: system,
            swarm,
            swarm_rx,
            sender_map: SenderMap::new(),
        }
    }

    // Poll from the swarm for events from remote peers, and from the `swarm_tx` channel for events from the local
    // actor, and forward them.
    pub async fn poll_swarm(mut self) {
        loop {
            select! {
                actor_event = self.swarm_rx.next().fuse() => {
                    if let Some((message, sender)) = actor_event {
                        self.handle_actor_request(message, sender)
                    } else {
                        return
                    }
                },
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event).await,
            };
        }
    }

    // Handle the messages that are received from other actors in the system..
    fn handle_actor_request(&mut self, event: CommunicationRequest<T>, sender: Sender) {
        match event {
            CommunicationRequest::RequestMsg {
                peer_id,
                client_str,
                request,
            } => {
                let r = RequestMessage {
                    req: request,
                    client_str,
                };
                let request_id = self.swarm.send_request(&peer_id, r);
                self.sender_map.insert(request_id, sender);
            }
            CommunicationRequest::ConnectPeerId(peer_id) => {
                if let Err(error) = Swarm::dial(&mut self.swarm, &peer_id) {
                    if let Some(sender) = sender {
                        let result = CommunicationResults::<U>::ConnectPeerResult(Err(error.into()));
                        sender.try_tell(result, None).unwrap();
                    }
                } else {
                    self.sender_map.insert(peer_id, sender);
                }
            }
            CommunicationRequest::ConnectPeerAddr(addr) => {
                if let Err(limit) = Swarm::dial_addr(&mut self.swarm, addr.clone()) {
                    if let Some(sender) = sender {
                        let result =
                            CommunicationResults::<U>::ConnectPeerResult(Err(ConnectPeerError::ConnectionLimit(limit)));
                        sender.try_tell(result, None).unwrap();
                    }
                } else {
                    self.sender_map.insert(addr, sender);
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
            _ => {}
        }
    }

    // Poll from the swarm for requests and responses from remote peers, and publish them in the channel.
    async fn handle_swarm_event<HandleErr>(
        &mut self,
        event: SwarmEvent<P2PEvent<RequestMessage<T>, ResponseMessage<U>>, HandleErr>,
    ) {
        match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => match boxed_event.deref().clone() {
                P2PReqResEvent::Req {
                    peer_id: _,
                    request_id,
                    request: RequestMessage { req, client_str },
                } => {
                    let res = if let Ok(client) = self.sys.select(&format!("/user/{}/", client_str.clone())) {
                        let handle = ask::ask_selection(&self.sys, &client, req);
                        if let Some(handle) = handle {
                            ResponseMessage(Ok(handle.await))
                        } else {
                            ResponseMessage(Err(client_str))
                        }
                    } else {
                        ResponseMessage(Err(client_str))
                    };
                    self.swarm.send_response(res, request_id).unwrap();
                }
                P2PReqResEvent::Res {
                    peer_id: _,
                    request_id,
                    response: ResponseMessage(res),
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let res = match res {
                            Ok(r) => Ok(r),
                            Err(e) => Err(RequestMessageError::NoClient(e)),
                        };
                        actor_ref
                            .try_tell(CommunicationResults::RequestMsgResult(res), None)
                            .unwrap();
                    }
                }
                P2PReqResEvent::InboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let msg = CommunicationResults::<U>::RequestMsgResult(Err(RequestMessageError::Inbound(error)));
                        actor_ref.try_tell(msg, None).unwrap();
                    }
                }
                P2PReqResEvent::OutboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let msg =
                            CommunicationResults::<U>::RequestMsgResult(Err(RequestMessageError::Outbound(error)));
                        actor_ref.try_tell(msg, None).unwrap();
                    }
                }
                _ => {}
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address },
                num_established: _,
            } => {
                let actor_ref = if let Some(actor) = self.sender_map.take(peer_id) {
                    actor
                } else if let Some(actor) = self.sender_map.take(address) {
                    actor
                } else {
                    None
                };
                if let Some(actor_ref) = actor_ref {
                    let msg = CommunicationResults::<U>::ConnectPeerResult(Ok(peer_id));
                    actor_ref.try_tell(msg, None).unwrap();
                }
            }
            SwarmEvent::UnreachableAddr {
                peer_id,
                address,
                error,
                attempts_remaining: 0,
            } => {
                let actor_ref = if let Some(actor) = self.sender_map.take(peer_id) {
                    actor
                } else if let Some(actor) = self.sender_map.take(address) {
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
                if let Some(Some(actor_ref)) = self.sender_map.take(address) {
                    let msg = CommunicationResults::<U>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    actor_ref.try_tell(msg, None).unwrap();
                }
            }
            _ => {}
        }
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

mod connections;
pub mod handler;
mod types;
use connections::PeerConnectionManager;
use futures::channel::oneshot;
use handler::RequestResponseHandler;
pub use handler::{MessageProtocol, ProtocolSupport};
use libp2p::{
    core::{
        connection::{ConnectionId, ListenerId},
        either::EitherOutput,
        ConnectedPoint, Multiaddr, PeerId,
    },
    mdns::Mdns,
    relay::Relay,
    swarm::{
        DialPeerCondition, IntoProtocolsHandler, IntoProtocolsHandlerSelect, NetworkBehaviour, NetworkBehaviourAction,
        NotifyHandler, PollParameters, ProtocolsHandler,
    },
};
use smallvec::SmallVec;
use std::{
    collections::{HashMap, VecDeque},
    error,
    sync::{atomic::AtomicU64, Arc},
    task::{Context, Poll},
    time::Duration,
};
pub use types::*;

#[derive(Debug, Clone)]
pub struct RequestResponseConfig {
    request_timeout: Duration,
    connection_timeout: Duration,
    protocol_support: ProtocolSupport,
}

impl Default for RequestResponseConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            protocol_support: ProtocolSupport::Full,
        }
    }
}

impl RequestResponseConfig {
    pub fn set_connection_keep_alive(&mut self, timeout: Duration) -> &mut Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn set_request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.request_timeout = timeout;
        self
    }

    pub fn set_protocol_support(&mut self, protocol_support: ProtocolSupport) -> &mut Self {
        self.protocol_support = protocol_support;
        self
    }
}

type NetworkAction<Proto> = NetworkBehaviourAction<
    <<<Proto as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <Proto as NetworkBehaviour>::OutEvent,
>;

pub struct RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    relay: Relay,

    supported_protocols: SmallVec<[MessageProtocol; 2]>,
    next_request_id: RequestId,
    next_inbound_id: Arc<AtomicU64>,
    config: RequestResponseConfig,
    pending_events: VecDeque<NetworkBehaviourAction<Request<Req, Res>, BehaviourEvent<Req, Res>>>,
    peer_connections: PeerConnectionManager,
    pending_outbound_requests: HashMap<PeerId, SmallVec<[Request<Req, Res>; 10]>>,
    pending_inbound_responses: HashMap<RequestId, oneshot::Sender<Res>>,
}

impl<Req, Res> RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub fn new(
        supported_protocols: Vec<MessageProtocol>,
        cfg: RequestResponseConfig,
        mdns: Mdns,
        relay: Relay,
    ) -> Self {
        RequestResponse {
            mdns,
            relay,
            supported_protocols: SmallVec::from_vec(supported_protocols),
            next_request_id: RequestId::new(1),
            next_inbound_id: Arc::new(AtomicU64::new(1)),
            config: cfg,
            pending_events: VecDeque::new(),
            peer_connections: PeerConnectionManager::new(),
            pending_outbound_requests: HashMap::new(),
            pending_inbound_responses: HashMap::new(),
        }
    }

    pub fn send_request(&mut self, peer: PeerId, request: Req) -> Option<ResponseReceiver<Res>> {
        self.config.protocol_support.outbound().then(|| {
            let request_id = self.next_request_id();
            let (response_sender, response_receiver) = oneshot::channel();
            let receiver = ResponseReceiver::new(peer, request_id, response_receiver);
            let request = Request {
                request_id,
                message: request,
                response_sender,
            };
            if let Some(request) = self.try_send_request(peer, request) {
                self.pending_events.push_back(NetworkBehaviourAction::DialPeer {
                    peer_id: peer,
                    condition: DialPeerCondition::Disconnected,
                });
                self.pending_outbound_requests.entry(peer).or_default().push(request);
            }
            receiver
        })
    }

    pub fn send_response(&mut self, request_id: RequestId, response: Res) -> Result<(), Res> {
        if let Some(channel) = self.pending_inbound_responses.remove(&request_id) {
            channel.send(response)
        } else {
            Err(response)
        }
    }

    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) {
        self.peer_connections.add_address(peer, address)
    }

    pub fn remove_address(&mut self, peer: PeerId, address: &Multiaddr) {
        self.peer_connections.remove_address(peer, address)
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.peer_connections.is_connected(peer)
    }

    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    fn try_send_request(&mut self, peer: PeerId, request: Request<Req, Res>) -> Option<Request<Req, Res>> {
        if let Some(connection_id) = self
            .peer_connections
            .new_request(&peer, request.request_id, &Direction::Inbound)
        {
            let event = NetworkBehaviourAction::NotifyHandler {
                peer_id: peer,
                handler: NotifyHandler::One(connection_id),
                event: request,
            };
            self.pending_events.push_back(event);
            None
        } else {
            Some(request)
        }
    }

    fn handle_connection_closed(&mut self, peer: &PeerId, conn_id: &ConnectionId) {
        if let Some(connection) = self.peer_connections.remove_connection(*peer, conn_id) {
            let mut events = Vec::new();
            let mut outbound_events = connection
                .pending_requests(&Direction::Outbound)
                .iter()
                .map(|request_id| {
                    let err = SendResponseError::ConnectionClosed;
                    let ev = RequestResponseEvent::SendResponse(Err(err));
                    (*request_id, ev)
                })
                .collect();
            let mut inbound_events = connection
                .pending_requests(&Direction::Inbound)
                .iter()
                .map(|request_id| {
                    let err = ReceiveResponseError::ConnectionClosed;
                    let ev = RequestResponseEvent::ReceiveResponse(Err(err));
                    (*request_id, ev)
                })
                .collect();
            events.append(&mut outbound_events);
            events.append(&mut inbound_events);
            events.into_iter().for_each(|(request_id, event)| {
                let event = BehaviourEvent {
                    peer: *peer,
                    request_id,
                    event,
                };
                let action = NetworkBehaviourAction::GenerateEvent(event);
                self.pending_events.push_back(action);
            })
        }
    }

    fn handler_handler_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Req, Res>) {
        let request_id = *event.request_id();
        let req_res_event = match event {
            HandlerOutEvent::SentRequest(_) => {
                debug_assert!(
                    self.peer_connections.is_connected(&peer),
                    "Expect to be connected to a peer after sending a request.",
                );
                RequestResponseEvent::SendRequest(Ok(()))
            }
            HandlerOutEvent::ReceivedResponse(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Inbound);
                debug_assert!(removed, "Expect request_id to be pending before receiving response.",);
                RequestResponseEvent::ReceiveResponse(Ok(()))
            }
            HandlerOutEvent::ReceiveResponseOmission(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Inbound);
                debug_assert!(removed, "Expect request_id to be pending before response is omitted.",);
                RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::ReceiveResponseOmission))
            }
            HandlerOutEvent::ReceivedRequest(request) => {
                let req_res_event = RequestResponseEvent::ReceiveRequest(Ok(request));
                match self
                    .peer_connections
                    .new_request(&peer, request_id, &Direction::Outbound)
                {
                    Some(_) => req_res_event,
                    None => {
                        let event = BehaviourEvent {
                            peer,
                            request_id,
                            event: req_res_event,
                        };
                        self.pending_events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                        RequestResponseEvent::SendResponse(Err(SendResponseError::ConnectionClosed))
                    }
                }
            }
            HandlerOutEvent::SentResponse(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before response is sent.");
                RequestResponseEvent::SendResponse(Ok(()))
            }
            HandlerOutEvent::SendResponseOmission(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before response is omitted.",);
                RequestResponseEvent::SendResponse(Err(SendResponseError::SendResponseOmission))
            }
            HandlerOutEvent::OutboundTimeout(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Inbound);
                debug_assert!(removed, "Expect request_id to be pending before request times out.");
                RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::Timeout))
            }
            HandlerOutEvent::InboundTimeout(_) => {
                self.peer_connections
                    .remove_request(&peer, &connection, &request_id, &Direction::Outbound);
                RequestResponseEvent::SendResponse(Err(SendResponseError::Timeout))
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(_) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, &Direction::Inbound);
                debug_assert!(removed, "Expect request_id to be pending before failing to connect.",);
                RequestResponseEvent::SendRequest(Err(SendRequestError::UnsupportedProtocols))
            }
            HandlerOutEvent::InboundUnsupportedProtocols(_) => {
                RequestResponseEvent::ReceiveRequest(Err(ReceiveRequestError::UnsupportedProtocols))
            }
        };
        let behaviour_event = BehaviourEvent {
            peer,
            request_id,
            event: req_res_event,
        };
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(behaviour_event));
    }
}

impl<Req, Res> NetworkBehaviour for RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type ProtocolsHandler = IntoProtocolsHandlerSelect<
        RequestResponseHandler<Req, Res>,
        IntoProtocolsHandlerSelect<
            <Mdns as NetworkBehaviour>::ProtocolsHandler,
            <Relay as NetworkBehaviour>::ProtocolsHandler,
        >,
    >;
    type OutEvent = BehaviourEvent<Req, Res>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        let handler = RequestResponseHandler::new(
            self.supported_protocols.clone(),
            self.config.protocol_support.clone(),
            self.config.connection_timeout,
            self.config.request_timeout,
            self.next_inbound_id.clone(),
        );
        let mdns_handler = self.mdns.new_handler();
        let relay_handler = self.relay.new_handler();
        IntoProtocolsHandler::select(handler, IntoProtocolsHandler::select(mdns_handler, relay_handler))
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = self
            .peer_connections
            .get_peer_addrs(peer)
            .map(|v| v.to_vec())
            .unwrap_or_default();
        addresses.extend(self.mdns.addresses_of_peer(peer));
        addresses.extend(self.relay.addresses_of_peer(peer));
        addresses
    }

    fn inject_connected(&mut self, peer: &PeerId) {
        self.relay.inject_connected(peer);
        if let Some(pending) = self.pending_outbound_requests.remove(peer) {
            for request in pending {
                let request = self.try_send_request(*peer, request);
                assert!(request.is_none());
            }
        }
    }

    fn inject_disconnected(&mut self, peer: &PeerId) {
        self.relay.inject_disconnected(peer);
        self.mdns.inject_disconnected(peer);
        self.peer_connections.remove_all_connections(peer);
    }

    fn inject_connection_established(&mut self, peer: &PeerId, conn_id: &ConnectionId, endpoint: &ConnectedPoint) {
        self.peer_connections
            .add_connection(*peer, *conn_id, endpoint.get_remote_address().clone());
        self.relay.inject_connection_established(peer, conn_id, endpoint);
    }

    fn inject_connection_closed(&mut self, peer: &PeerId, conn_id: &ConnectionId, endpoint: &ConnectedPoint) {
        self.handle_connection_closed(peer, conn_id);
        self.relay.inject_connection_closed(peer, conn_id, endpoint);
    }

    fn inject_address_change(&mut self, _: &PeerId, _: &ConnectionId, _old: &ConnectedPoint, _new: &ConnectedPoint) {}

    fn inject_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: <<Self::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    ) {
        match event {
            EitherOutput::First(ev) => self.handler_handler_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::First(ev)) => self.mdns.inject_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::Second(ev)) => self.relay.inject_event(peer, connection, ev),
        }
    }

    fn inject_addr_reach_failure(&mut self, _peer_id: Option<&PeerId>, _addr: &Multiaddr, _error: &dyn error::Error) {}

    fn inject_dial_failure(&mut self, peer: &PeerId) {
        if let Some(pending) = self.pending_outbound_requests.remove(peer) {
            for request in pending {
                self.pending_events
                    .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent {
                        peer: *peer,
                        request_id: request.request_id,
                        event: RequestResponseEvent::SendRequest(Err(SendRequestError::DialFailure)),
                    }));
            }
        }
        self.relay.inject_dial_failure(peer);
    }

    fn inject_new_listener(&mut self, _id: ListenerId) {}

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        self.mdns.inject_new_listen_addr(id, addr);
    }

    fn inject_expired_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {}

    fn inject_listener_error(&mut self, _id: ListenerId, _err: &(dyn std::error::Error + 'static)) {}

    fn inject_listener_closed(&mut self, _id: ListenerId, _reason: Result<(), &std::io::Error>) {}

    fn inject_new_external_addr(&mut self, _addr: &Multiaddr) {}

    fn inject_expired_external_addr(&mut self, _addr: &Multiaddr) {}

    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl PollParameters) -> Poll<NetworkAction<Self>> {
        let _ = self.mdns.poll(cx, params);
        if let Some(action) = self.pending_events.pop_front() {
            match action {
                NetworkBehaviourAction::GenerateEvent(event) => {
                    return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event))
                }
                NetworkBehaviourAction::DialAddress { address } => {
                    return Poll::Ready(NetworkBehaviourAction::DialAddress { address })
                }
                NetworkBehaviourAction::DialPeer { peer_id, condition } => {
                    return Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition })
                }
                NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id,
                        handler,
                        event: EitherOutput::First(event),
                    })
                }
                _ => {}
            };
        } else if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }
        if let Poll::Ready(action) = self.relay.poll(cx, params) {
            match action {
                NetworkBehaviourAction::DialPeer { peer_id, condition } => {
                    return Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition })
                }
                NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id,
                        handler,
                        event: EitherOutput::Second(EitherOutput::Second(event)),
                    })
                }
                _ => {}
            }
        }
        Poll::Pending
    }
}

const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

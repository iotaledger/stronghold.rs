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

pub mod handler;
mod types;

pub use handler::{MessageEvent, MessageProtocol, ProtocolSupport};
pub use types::*;

use futures::channel::oneshot;
use handler::{HandlerInEvent, HandlerOutEvent, RequestResponseHandler};
use libp2p::{
    core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId},
    swarm::{DialPeerCondition, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters},
};
use smallvec::SmallVec;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{atomic::AtomicU64, Arc},
    task::{Context, Poll},
    time::Duration,
};

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

pub struct RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    supported_protocols: SmallVec<[MessageProtocol; 2]>,
    next_request_id: RequestId,
    next_inbound_id: Arc<AtomicU64>,
    config: RequestResponseConfig,
    pending_events: VecDeque<NetworkBehaviourAction<HandlerInEvent<Req, Res>, BehaviourEvent<Req, Res>>>,
    connected: HashMap<PeerId, SmallVec<[Connection; 2]>>,
    addresses: HashMap<PeerId, SmallVec<[Multiaddr; 6]>>,
    pending_outbound_requests: HashMap<PeerId, SmallVec<[(RequestId, Req); 10]>>,
    pending_inbound_responses: HashMap<RequestId, oneshot::Sender<Res>>,
}

impl<Req, Res> RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub fn new(supported_protocols: Vec<MessageProtocol>, cfg: RequestResponseConfig) -> Self {
        RequestResponse {
            supported_protocols: SmallVec::from_vec(supported_protocols),
            next_request_id: RequestId::new(1),
            next_inbound_id: Arc::new(AtomicU64::new(1)),
            config: cfg,
            pending_events: VecDeque::new(),
            connected: HashMap::new(),
            addresses: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            pending_inbound_responses: HashMap::new(),
        }
    }

    pub fn send_request(&mut self, peer: &PeerId, request: Req) -> Option<RequestId> {
        self.config.protocol_support.outbound().then(|| {
            let request_id = self.next_request_id();
            if let Some(request) = self.try_send_request(peer, request_id, request) {
                self.pending_events.push_back(NetworkBehaviourAction::DialPeer {
                    peer_id: *peer,
                    condition: DialPeerCondition::Disconnected,
                });
                self.pending_outbound_requests
                    .entry(*peer)
                    .or_default()
                    .push((request_id, request));
            }
            request_id
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
        self.addresses.entry(*peer).or_default().push(address);
    }

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        let mut last = false;
        if let Some(addresses) = self.addresses.get_mut(peer) {
            addresses.retain(|a| a != address);
            last = addresses.is_empty();
        }
        if last {
            self.addresses.remove(peer);
        }
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        if let Some(connections) = self.connected.get(peer) {
            !connections.is_empty()
        } else {
            false
        }
    }

    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    fn try_send_request(&mut self, peer: &PeerId, request_id: RequestId, request: Req) -> Option<Req> {
        if let Some(connections) = self.connected.get_mut(peer) {
            if connections.is_empty() {
                return Some(request);
            }
            let index = (request_id.value() as usize) % connections.len();
            let conn = &mut connections[index];

            conn.pending_inbound_responses.insert(request_id);
            self.pending_events.push_back(NetworkBehaviourAction::NotifyHandler {
                peer_id: *peer,
                handler: NotifyHandler::One(conn.id),
                event: HandlerInEvent::SendRequest { request, request_id },
            });
            None
        } else {
            Some(request)
        }
    }

    fn remove_pending_outbound_response(
        &mut self,
        peer: &PeerId,
        connection: ConnectionId,
        request: &RequestId,
    ) -> bool {
        self.get_connection_mut(peer, connection)
            .map(|c| c.pending_outbound_responses.remove(request))
            .unwrap_or(false)
    }

    fn remove_pending_inbound_response(
        &mut self,
        peer: &PeerId,
        connection: ConnectionId,
        request: &RequestId,
    ) -> bool {
        self.get_connection_mut(peer, connection)
            .map(|c| c.pending_inbound_responses.remove(request))
            .unwrap_or(false)
    }

    fn get_connection_mut(&mut self, peer: &PeerId, connection: ConnectionId) -> Option<&mut Connection> {
        self.connected
            .get_mut(peer)
            .and_then(|connections| connections.iter_mut().find(|c| c.id == connection))
    }
}

impl<Req, Res> NetworkBehaviour for RequestResponse<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type ProtocolsHandler = RequestResponseHandler<Req, Res>;
    type OutEvent = BehaviourEvent<Req, Res>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        RequestResponseHandler::new(
            self.supported_protocols.clone(),
            self.config.protocol_support.clone(),
            self.config.connection_timeout,
            self.config.request_timeout,
            self.next_inbound_id.clone(),
        )
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = Vec::new();
        if let Some(connections) = self.connected.get(peer) {
            addresses.extend(connections.iter().filter_map(|c| c.address.clone()))
        }
        if let Some(more) = self.addresses.get(peer) {
            addresses.extend(more.into_iter().cloned());
        }
        addresses
    }

    fn inject_connected(&mut self, peer: &PeerId) {
        if let Some(pending) = self.pending_outbound_requests.remove(peer) {
            for (request_id, request) in pending {
                let request = self.try_send_request(peer, request_id, request);
                assert!(request.is_none());
            }
        }
    }

    fn inject_connection_established(&mut self, peer: &PeerId, conn: &ConnectionId, endpoint: &ConnectedPoint) {
        let address = match endpoint {
            ConnectedPoint::Dialer { address } => Some(address.clone()),
            ConnectedPoint::Listener { .. } => None,
        };
        self.connected
            .entry(*peer)
            .or_default()
            .push(Connection::new(*conn, address));
    }

    fn inject_connection_closed(&mut self, peer_id: &PeerId, conn: &ConnectionId, _: &ConnectedPoint) {
        let connections = self
            .connected
            .get_mut(peer_id)
            .expect("Expected some established connection to peer before closing.");

        let connection = connections
            .iter()
            .position(|c| &c.id == conn)
            .map(|p: usize| connections.remove(p))
            .expect("Expected connection to be established before closing.");

        if connections.is_empty() {
            self.connected.remove(peer_id);
        }

        for request_id in connection.pending_outbound_responses {
            self.pending_events
                .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent {
                    peer_id: *peer_id,
                    request_id,
                    event: RequestResponseEvent::SendResponse(Err(SendResponseError::ConnectionClosed)),
                }));
        }

        for request_id in connection.pending_inbound_responses {
            self.pending_events
                .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent {
                    peer_id: *peer_id,
                    request_id,
                    event: RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::ConnectionClosed)),
                }));
        }
    }

    fn inject_disconnected(&mut self, peer: &PeerId) {
        self.connected.remove(peer);
    }

    fn inject_dial_failure(&mut self, peer: &PeerId) {
        if let Some(pending) = self.pending_outbound_requests.remove(peer) {
            for (request_id, _) in pending {
                self.pending_events
                    .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent {
                        peer_id: *peer,
                        request_id,
                        event: RequestResponseEvent::SendRequest(Err(SendRequestError::DialFailure)),
                    }));
            }
        }
    }

    fn inject_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Req, Res>) {
        let request_id = *event.request_id();
        let req_res_event = match event {
            HandlerOutEvent::ReceiveResponse {
                ref request_id,
                response,
            } => {
                let removed = self.remove_pending_inbound_response(&peer, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before receiving response.",);
                RequestResponseEvent::ReceiveResponse(Ok(response))
            }
            HandlerOutEvent::ReceiveRequest {
                request_id,
                request,
                sender,
            } => {
                let request = Request {
                    request,
                    response_channel: sender,
                };
                let req_res_event = RequestResponseEvent::ReceiveRequest(Ok(request));
                match self.get_connection_mut(&peer, connection) {
                    Some(connection) => {
                        let inserted = connection.pending_outbound_responses.insert(request_id);
                        debug_assert!(inserted, "Expect id of new request to be unknown.");
                        req_res_event
                    }
                    None => {
                        let event = BehaviourEvent {
                            peer_id: peer,
                            request_id,
                            event: req_res_event,
                        };
                        self.pending_events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                        RequestResponseEvent::SendResponse(Err(SendResponseError::ConnectionClosed))
                    }
                }
            }
            HandlerOutEvent::ResponseSent(ref request_id) => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before response is sent.");
                RequestResponseEvent::SendResponse(Ok(()))
            }
            HandlerOutEvent::ResponseOmission(ref request_id) => {
                let removed = self.remove_pending_outbound_response(&peer, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before response is omitted.",);
                RequestResponseEvent::SendResponse(Err(SendResponseError::ResponseOmission))
            }
            HandlerOutEvent::OutboundTimeout(ref request_id) => {
                let removed = self.remove_pending_inbound_response(&peer, connection, &request_id);
                debug_assert!(removed, "Expect request_id to be pending before request times out.");
                RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::Timeout))
            }
            HandlerOutEvent::InboundTimeout(ref request_id) => {
                self.remove_pending_outbound_response(&peer, connection, request_id);
                RequestResponseEvent::SendResponse(Err(SendResponseError::Timeout))
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(ref request_id) => {
                let removed = self.remove_pending_inbound_response(&peer, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before failing to connect.",);
                RequestResponseEvent::SendRequest(Err(SendRequestError::UnsupportedProtocols))
            }
            HandlerOutEvent::InboundUnsupportedProtocols(_) => {
                RequestResponseEvent::ReceiveRequest(Err(ReceiveRequestError::UnsupportedProtocols))
            }
        };
        let behaviour_event = BehaviourEvent {
            peer_id: peer,
            request_id,
            event: req_res_event,
        };
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(behaviour_event));
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<HandlerInEvent<Req, Res>, Self::OutEvent>> {
        if let Some(ev) = self.pending_events.pop_front() {
            return Poll::Ready(ev);
        } else if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }

        Poll::Pending
    }
}

const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

struct Connection {
    id: ConnectionId,
    address: Option<Multiaddr>,
    pending_outbound_responses: HashSet<RequestId>,
    pending_inbound_responses: HashSet<RequestId>,
}

impl Connection {
    fn new(id: ConnectionId, address: Option<Multiaddr>) -> Self {
        Self {
            id,
            address,
            pending_outbound_responses: Default::default(),
            pending_inbound_responses: Default::default(),
        }
    }
}

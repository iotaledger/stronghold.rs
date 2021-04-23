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
    collections::{HashMap, HashSet, VecDeque},
    error,
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

    fn handler_handler_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: HandlerOutEvent<Req, Res>) {
        let request_id = *event.request_id();
        let req_res_event = match event {
            HandlerOutEvent::ReceiveResponse {
                ref request_id,
                response,
            } => {
                let removed = self.remove_pending_inbound_response(&peer_id, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before receiving response.",);
                RequestResponseEvent::ReceiveResponse(Ok(response))
            }
            HandlerOutEvent::ReceiveRequest { request_id, request } => {
                let req_res_event = RequestResponseEvent::ReceiveRequest(Ok(request));
                match self.get_connection_mut(&peer_id, connection) {
                    Some(connection) => {
                        let inserted = connection.pending_outbound_responses.insert(request_id);
                        debug_assert!(inserted, "Expect id of new request to be unknown.");
                        req_res_event
                    }
                    None => {
                        let event = BehaviourEvent {
                            peer_id,
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
                let removed = self.remove_pending_outbound_response(&peer_id, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before response is sent.");
                RequestResponseEvent::SendResponse(Ok(()))
            }
            HandlerOutEvent::ResponseOmission(ref request_id) => {
                let removed = self.remove_pending_outbound_response(&peer_id, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before response is omitted.",);
                RequestResponseEvent::SendResponse(Err(SendResponseError::ResponseOmission))
            }
            HandlerOutEvent::OutboundTimeout(ref request_id) => {
                let removed = self.remove_pending_inbound_response(&peer_id, connection, &request_id);
                debug_assert!(removed, "Expect request_id to be pending before request times out.");
                RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::Timeout))
            }
            HandlerOutEvent::InboundTimeout(ref request_id) => {
                self.remove_pending_outbound_response(&peer_id, connection, request_id);
                RequestResponseEvent::SendResponse(Err(SendResponseError::Timeout))
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(ref request_id) => {
                let removed = self.remove_pending_inbound_response(&peer_id, connection, request_id);
                debug_assert!(removed, "Expect request_id to be pending before failing to connect.",);
                RequestResponseEvent::SendRequest(Err(SendRequestError::UnsupportedProtocols))
            }
            HandlerOutEvent::InboundUnsupportedProtocols(_) => {
                RequestResponseEvent::ReceiveRequest(Err(ReceiveRequestError::UnsupportedProtocols))
            }
        };
        let behaviour_event = BehaviourEvent {
            peer_id,
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

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = Vec::new();
        if let Some(connections) = self.connected.get(peer_id) {
            addresses.extend(connections.iter().filter_map(|c| c.address.clone()))
        }
        if let Some(more) = self.addresses.get(peer_id) {
            addresses.extend(more.into_iter().cloned());
        }
        addresses.extend(self.mdns.addresses_of_peer(peer_id));
        addresses.extend(self.relay.addresses_of_peer(peer_id));
        addresses
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {
        self.relay.inject_connected(peer_id);
        if let Some(pending) = self.pending_outbound_requests.remove(peer_id) {
            for (request_id, request) in pending {
                let request = self.try_send_request(peer_id, request_id, request);
                assert!(request.is_none());
            }
        }
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        self.relay.inject_disconnected(peer_id);
        self.connected.remove(peer_id);
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        let address = match endpoint {
            ConnectedPoint::Dialer { address } => Some(address.clone()),
            ConnectedPoint::Listener { .. } => None,
        };
        self.connected
            .entry(*peer_id)
            .or_default()
            .push(Connection::new(*connection_id, address));
        self.relay
            .inject_connection_established(peer_id, connection_id, endpoint);
    }

    fn inject_connection_closed(&mut self, peer_id: &PeerId, conn: &ConnectionId, endpoint: &ConnectedPoint) {
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
        self.relay.inject_connection_closed(peer_id, conn, endpoint);
    }

    fn inject_address_change(&mut self, _: &PeerId, _: &ConnectionId, _old: &ConnectedPoint, _new: &ConnectedPoint) {}

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <<Self::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    ) {
        match event {
            EitherOutput::First(ev) => self.handler_handler_event(peer_id, connection, ev),
            EitherOutput::Second(EitherOutput::First(ev)) => self.mdns.inject_event(peer_id, connection, ev),
            EitherOutput::Second(EitherOutput::Second(ev)) => self.relay.inject_event(peer_id, connection, ev),
        }
    }

    fn inject_addr_reach_failure(&mut self, _peer_id: Option<&PeerId>, _addr: &Multiaddr, _error: &dyn error::Error) {}

    fn inject_dial_failure(&mut self, peer_id: &PeerId) {
        if let Some(pending) = self.pending_outbound_requests.remove(peer_id) {
            for (request_id, _) in pending {
                self.pending_events
                    .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent {
                        peer_id: *peer_id,
                        request_id,
                        event: RequestResponseEvent::SendRequest(Err(SendRequestError::DialFailure)),
                    }));
            }
        }
        self.relay.inject_dial_failure(peer_id);
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

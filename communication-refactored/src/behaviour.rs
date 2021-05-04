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
use connections::{Direction, PeerConnectionManager};
use futures::channel::oneshot;
use handler::ConnectionHandler;
pub use handler::{CommunicationProtocol, ProtocolSupport};
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

type NetworkAction<Proto> = NetworkBehaviourAction<
    <<<Proto as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <Proto as NetworkBehaviour>::OutEvent,
>;

type PedingOutboundRequests<Rq, Rs> = SmallVec<[(RequestId, Request<Rq, Rs>); 10]>;

#[derive(Debug, Clone)]
pub struct NetBehaviourConfig {
    request_timeout: Duration,
    connection_timeout: Duration,
    protocol_support: ProtocolSupport,
}

impl Default for NetBehaviourConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            protocol_support: ProtocolSupport::Full,
        }
    }
}

impl NetBehaviourConfig {
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

pub struct NetBehaviour<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    relay: Relay,

    supported_protocols: SmallVec<[CommunicationProtocol; 2]>,
    next_request_id: RequestId,
    next_inbound_id: Arc<AtomicU64>,
    config: NetBehaviourConfig,
    pending_events: VecDeque<NetworkBehaviourAction<HandlerInEvent<Rq, Rs>, BehaviourEvent<Rq, Rs>>>,
    peer_connections: PeerConnectionManager,
    pending_outbound_requests: HashMap<PeerId, PedingOutboundRequests<Rq, Rs>>,
}

impl<Rq, Rs> NetBehaviour<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    pub fn new(
        supported_protocols: Vec<CommunicationProtocol>,
        cfg: NetBehaviourConfig,
        mdns: Mdns,
        relay: Relay,
    ) -> Self {
        NetBehaviour {
            mdns,
            relay,
            supported_protocols: SmallVec::from_vec(supported_protocols),
            next_request_id: RequestId::new(1),
            next_inbound_id: Arc::new(AtomicU64::new(1)),
            config: cfg,
            pending_events: VecDeque::new(),
            peer_connections: PeerConnectionManager::new(),
            pending_outbound_requests: HashMap::new(),
        }
    }

    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> Option<ResponseReceiver<Rs>> {
        self.config.protocol_support.outbound().then(|| {
            let request_id = self.next_request_id();
            let (response_sender, response_receiver) = oneshot::channel();
            let receiver = ResponseReceiver::new(peer, request_id, response_receiver);
            let request = Request {
                message: request,
                response_sender,
            };
            if let Some(request) = self.try_send_request(peer, request_id, request) {
                self.pending_events.push_back(NetworkBehaviourAction::DialPeer {
                    peer_id: peer,
                    condition: DialPeerCondition::Disconnected,
                });
                self.pending_outbound_requests
                    .entry(peer)
                    .or_default()
                    .push((request_id, request));
            }
            receiver
        })
    }

    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) {
        self.peer_connections.add_address(peer, address)
    }

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        self.peer_connections.remove_address(peer, address)
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.peer_connections.is_connected(peer)
    }

    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    fn try_send_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: Request<Rq, Rs>,
    ) -> Option<Request<Rq, Rs>> {
        if let Some(connection_id) = self
            .peer_connections
            .new_request(&peer, request_id, Direction::Outbound)
        {
            let event = NetworkBehaviourAction::NotifyHandler {
                peer_id: peer,
                handler: NotifyHandler::One(connection_id),
                event: HandlerInEvent { request_id, request },
            };
            self.pending_events.push_back(event);
            None
        } else {
            Some(request)
        }
    }

    fn handle_connection_closed(&mut self, peer: &PeerId, conn_id: &ConnectionId) {
        if let Some(connection) = self.peer_connections.remove_connection(*peer, conn_id) {
            connection.pending_outbound_requests.into_iter().for_each(|request_id| {
                let event = BehaviourEvent::ReceiveResponse {
                    peer: *peer,
                    request_id,
                    result: Err(RecvResponseErr::ConnectionClosed),
                };
                let action = NetworkBehaviourAction::GenerateEvent(event);
                self.pending_events.push_back(action);
            });
        }
    }

    fn handler_handler_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Rq, Rs>) {
        let event = match event {
            HandlerOutEvent::ReceivedResponse(request_id) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before receiving response.",);
                BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result: Ok(()),
                }
            }
            HandlerOutEvent::RecvResponseOmission(request_id) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before response is omitted.",);
                BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result: Err(RecvResponseErr::RecvResponseOmission),
                }
            }
            HandlerOutEvent::ReceivedRequest { request_id, request } => {
                self.peer_connections.new_request(&peer, request_id, Direction::Inbound);
                BehaviourEvent::ReceiveRequest {
                    peer,
                    request_id,
                    request,
                }
            }
            HandlerOutEvent::OutboundTimeout(request_id) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before request times out.");
                BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result: Err(RecvResponseErr::Timeout),
                }
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => {
                let removed =
                    self.peer_connections
                        .remove_request(&peer, &connection, &request_id, Direction::Outbound);
                debug_assert!(removed, "Expect request_id to be pending before failing to connect.",);
                BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result: Err(RecvResponseErr::UnsupportedProtocols),
                }
            }
            HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::SentResponse(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id) => {
                self.peer_connections
                    .remove_request(&peer, &connection, &request_id, Direction::Inbound);
                return;
            }
        };
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(event));
    }
}

impl<Rq, Rs> NetworkBehaviour for NetBehaviour<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    type ProtocolsHandler = IntoProtocolsHandlerSelect<
        ConnectionHandler<Rq, Rs>,
        IntoProtocolsHandlerSelect<
            <Mdns as NetworkBehaviour>::ProtocolsHandler,
            <Relay as NetworkBehaviour>::ProtocolsHandler,
        >,
    >;
    type OutEvent = BehaviourEvent<Rq, Rs>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        let handler = ConnectionHandler::new(
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
            for (request_id, request) in pending {
                let request = self.try_send_request(*peer, request_id, request);
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
            for (request_id, _) in pending {
                self.pending_events
                    .push_back(NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceiveResponse {
                        peer: *peer,
                        request_id,
                        result: Err(RecvResponseErr::DialFailure),
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

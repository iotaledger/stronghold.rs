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

mod protocol;
use super::EMPTY_QUEUE_SHRINK_THRESHOLD;
use crate::{firewall::Rule, RequestId, RequestMessage, RqRsMessage};
use futures::{channel::oneshot, future::BoxFuture, prelude::*, stream::FuturesUnordered};
use libp2p::{
    core::upgrade::{NegotiationError, UpgradeError},
    swarm::{
        protocols_handler::{KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr},
        SubstreamProtocol,
    },
};
pub use protocol::{CommunicationProtocol, RequestProtocol, ResponseProtocol};
use smallvec::SmallVec;
use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

type ProtocolsHandlerEventType<Rq, Rs> = ProtocolsHandlerEvent<
    RequestProtocol<Rq, Rs>,
    RequestId,
    <ConnectionHandler<Rq, Rs> as ProtocolsHandler>::OutEvent,
    <ConnectionHandler<Rq, Rs> as ProtocolsHandler>::Error,
>;

type PendingInboundFuture<Rq, Rs> = BoxFuture<'static, Result<(RequestId, RequestMessage<Rq, Rs>), oneshot::Canceled>>;

/// The level of support for the [`CommunicationProtocol`] protocol.
/// This is set according to the currently effective firewall rules for the remote peer.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolSupport {
    /// The protocol is only supported for inbound requests.
    Inbound,
    /// The protocol is only supported for outbound requests.
    Outbound,
    /// The protocol is supported for inbound and outbound requests.
    Full,
    /// Neither inbound, nor outbound requests are supported.
    None,
}

impl Default for ProtocolSupport {
    fn default() -> Self {
        ProtocolSupport::None
    }
}

impl ProtocolSupport {
    /// Derive the supported protocols from the firewall rules.
    /// A direction will only be not supported if the firewall is configured to reject all request in that direction.
    pub fn from_rules(inbound: Option<&Rule>, outbound: Option<&Rule>) -> Self {
        let allow_inbound = inbound.map(|r| !r.is_reject_all()).unwrap_or(true);
        let allow_outbound = outbound.map(|r| !r.is_reject_all()).unwrap_or(true);
        match allow_inbound && allow_outbound {
            true => ProtocolSupport::Full,
            _ if allow_inbound => ProtocolSupport::Inbound,
            _ if allow_outbound => ProtocolSupport::Outbound,
            _ => ProtocolSupport::None,
        }
    }

    /// Whether inbound requests are supported.
    pub fn is_inbound(&self) -> bool {
        match self {
            ProtocolSupport::Inbound | ProtocolSupport::Full => true,
            ProtocolSupport::Outbound | ProtocolSupport::None => false,
        }
    }

    /// Whether outbound requests are supported.
    pub fn is_outbound(&self) -> bool {
        match self {
            ProtocolSupport::Outbound | ProtocolSupport::Full => true,
            ProtocolSupport::Inbound | ProtocolSupport::None => false,
        }
    }
}

/// Events emitted in `NetBehaviour::poll` and injected to [`ConnectionHandler::inject_event`].
#[derive(Debug)]
pub enum HandlerInEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    /// Send an outbound request.
    SendRequest {
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    },
    /// Set the protocol support for inbound and outbound requests.
    /// This will be sent to the handler when the connection is first established,
    /// and each time the effective firewall rules for the remote change.
    SetProtocolSupport(ProtocolSupport),
}

/// Events emitted in [`ConnectionHandler::poll`] and injected to `NetBehaviour::inject_event`.
#[derive(Debug)]
pub enum HandlerOutEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    /// Received an inbound request from remote.
    ReceivedRequest {
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    },
    /// A response for an inbound requests was successfully sent.
    SentResponse(RequestId),
    /// The response channel closed from the sender side before a response was sent.
    SendResponseOmission(RequestId),
    /// Timeout on sending a response.
    InboundTimeout(RequestId),
    /// The inbound request was rejected because the local peer does not support any of the requested protocols.
    /// This could be either because the protocols differ, or because the local firewall rejects all inbound requests.
    InboundUnsupportedProtocols(RequestId),

    /// A response for an outbound requests was successfully received.
    ReceivedResponse(RequestId),
    /// A response for an outbound requests was received, but the response channel closed on the receiving side before
    /// the response was forwarded.
    RecvResponseOmission(RequestId),
    /// Timeout on receiving a response.
    OutboundTimeout(RequestId),
    /// The outbound request was rejected because the remote peer does not support any of the requested protocols.
    /// This could be either because the protocols differ, or because the remote firewall rejects all inbound requests.
    OutboundUnsupportedProtocols(RequestId),
}

/// Handler for a single connection to a remote peer.
/// One connection can have multiple substreams that each either negotiate the [`RequestProtocol`] or the
/// [`ResponseProtocol`] by performing the respective handshake (send `Rq` - receive `Rs` | receive `Rq` - send `Rs`).
pub struct ConnectionHandler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    /// Protocol version that are potentially supported.
    supported_protocols: SmallVec<[CommunicationProtocol; 2]>,
    /// Protocol support according the the firewall configuration for the remote peer.
    protocol_support: ProtocolSupport,
    /// Timeout for negotiating a handshake on a substream i.g. sending a requests and receiving the response.
    request_timeout: Duration,
    /// Timeout for an idle connection.
    keep_alive_timeout: Duration,

    /// Current setting whether the connection to the remote should be kept alive.
    /// This is set according to timeout config and pending requests.
    keep_alive: KeepAlive,
    // Request id assigned to the next inbound request.
    inbound_request_id: Arc<AtomicU64>,

    /// Fatal error in connection.
    pending_error: Option<ProtocolsHandlerUpgrErr<io::Error>>,

    /// Pending events to emit to the `NetBehaviour`
    pending_events: VecDeque<HandlerOutEvent<Rq, Rs>>,
    /// Pending outbound request that require a new [`ProtocolsHandlerEvent::OutboundSubstreamRequest`].
    pending_out_req: VecDeque<(RequestId, RequestMessage<Rq, Rs>)>,
    /// Pending inbound requests for which a [`ResponseProtocol`] was created, but no request message was received yet.
    pending_in_req: FuturesUnordered<PendingInboundFuture<Rq, Rs>>,
}

impl<Rq, Rs> ConnectionHandler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    pub(super) fn new(
        supported_protocols: SmallVec<[CommunicationProtocol; 2]>,
        protocol_support: ProtocolSupport,
        keep_alive_timeout: Duration,
        request_timeout: Duration,
        inbound_request_id: Arc<AtomicU64>,
    ) -> Self {
        Self {
            supported_protocols,
            protocol_support,
            request_timeout,
            keep_alive_timeout,
            keep_alive: KeepAlive::Yes,
            inbound_request_id,
            pending_error: None,
            pending_events: VecDeque::new(),
            pending_out_req: VecDeque::new(),
            pending_in_req: FuturesUnordered::new(),
        }
    }

    /// Create a new [`RequestProtocol`] for an outbound request.
    fn new_outbound_protocol(
        &mut self,
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    ) -> SubstreamProtocol<RequestProtocol<Rq, Rs>, RequestId> {
        let protocols = self
            .protocol_support
            .is_outbound()
            .then(|| self.supported_protocols.clone())
            .unwrap_or_default();
        let proto = RequestProtocol { protocols, request };
        SubstreamProtocol::new(proto, request_id).with_timeout(self.request_timeout)
    }

    /// Create a new [`ResponseProtocol`] for an inbound request.
    fn new_inbound_protocol(&self) -> SubstreamProtocol<ResponseProtocol<Rq, Rs>, RequestId> {
        // Assign a new request id to the expected request.
        let request_id = RequestId::new(self.inbound_request_id.fetch_add(1, Ordering::Relaxed));

        // Channel for the [`ResponseProtocol`] to forward the inbound request.
        let (request_tx, request_rx) = oneshot::channel();

        let protocols = self
            .protocol_support
            .is_inbound()
            .then(|| self.supported_protocols.clone())
            .unwrap_or_default();

        let proto = ResponseProtocol { protocols, request_tx };

        self.pending_in_req
            .push(request_rx.map_ok(move |request| (request_id, request)).boxed());

        SubstreamProtocol::new(proto, request_id).with_timeout(self.request_timeout)
    }
}

impl<Rq, Rs> ProtocolsHandler for ConnectionHandler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    type InEvent = HandlerInEvent<Rq, Rs>;
    type OutEvent = HandlerOutEvent<Rq, Rs>;
    type Error = ProtocolsHandlerUpgrErr<io::Error>;
    type InboundProtocol = ResponseProtocol<Rq, Rs>;
    type OutboundProtocol = RequestProtocol<Rq, Rs>;
    type InboundOpenInfo = RequestId;
    type OutboundOpenInfo = RequestId;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        self.new_inbound_protocol()
    }

    // Successfully received a requests and potentially send a response.
    fn inject_fully_negotiated_inbound(&mut self, send_response: bool, request_id: RequestId) {
        let event = send_response
            .then(|| HandlerOutEvent::SentResponse(request_id))
            .unwrap_or(HandlerOutEvent::SendResponseOmission(request_id));
        self.pending_events.push_back(event);
    }

    // Successfully send a requests and potentially received a response.
    fn inject_fully_negotiated_outbound(&mut self, received_response: bool, request_id: RequestId) {
        let event = received_response
            .then(|| HandlerOutEvent::ReceivedResponse(request_id))
            .unwrap_or(HandlerOutEvent::RecvResponseOmission(request_id));
        self.pending_events.push_back(event);
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            HandlerInEvent::SendRequest { request_id, request } => {
                self.pending_out_req.push_back((request_id, request));
                self.keep_alive = KeepAlive::Yes;
            }
            HandlerInEvent::SetProtocolSupport(ps) => {
                self.protocol_support = ps;
            }
        }
    }

    fn inject_dial_upgrade_error(&mut self, request_id: RequestId, error: ProtocolsHandlerUpgrErr<io::Error>) {
        match error {
            ProtocolsHandlerUpgrErr::Timeout => {
                self.pending_events
                    .push_back(HandlerOutEvent::OutboundTimeout(request_id));
            }
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                self.pending_events
                    .push_back(HandlerOutEvent::OutboundUnsupportedProtocols(request_id));
            }
            _ => {
                // Fatal error
                self.pending_error = Some(error);
            }
        }
    }

    fn inject_listen_upgrade_error(&mut self, request_id: RequestId, error: ProtocolsHandlerUpgrErr<io::Error>) {
        match error {
            ProtocolsHandlerUpgrErr::Timeout => {
                self.pending_events
                    .push_back(HandlerOutEvent::InboundTimeout(request_id));
            }
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                self.pending_events
                    .push_back(HandlerOutEvent::InboundUnsupportedProtocols(request_id));
            }
            _ => {
                // Fatal error
                self.pending_error = Some(error);
            }
        }
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        if let ProtocolSupport::None = self.protocol_support {
            // Immediately close connection if per se no requests are allowed.
            KeepAlive::No
        } else {
            self.keep_alive
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ProtocolsHandlerEventType<Rq, Rs>> {
        // Check for fatal error.
        if let Some(err) = self.pending_error.take() {
            return Poll::Ready(ProtocolsHandlerEvent::Close(err));
        }
        // Emit events to `NetBehaviour`.
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ProtocolsHandlerEvent::Custom(event));
        }
        if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }
        // Forward inbound requests to `NetBehaviour` once the request was read from the substream.
        while let Poll::Ready(Some(result)) = self.pending_in_req.poll_next_unpin(cx) {
            if let Ok((request_id, request)) = result {
                self.keep_alive = KeepAlive::Yes;
                return Poll::Ready(ProtocolsHandlerEvent::Custom(HandlerOutEvent::ReceivedRequest {
                    request_id,
                    request,
                }));
            }
        }
        // Create new outbound substream with `RequestProtocol` for outbound requests.
        if let Some((request_id, request)) = self.pending_out_req.pop_front() {
            self.keep_alive = KeepAlive::Yes;
            let protocol = self.new_outbound_protocol(request_id, request);
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol });
        }
        if self.pending_out_req.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_out_req.shrink_to_fit();
        }
        // Set timeout for keeping the connection alive.
        if self.keep_alive.is_yes() {
            let until = Instant::now() + self.request_timeout + self.keep_alive_timeout;
            self.keep_alive = KeepAlive::Until(until);
        }
        Poll::Pending
    }
}

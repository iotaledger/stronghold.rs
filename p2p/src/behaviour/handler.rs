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
use crate::{RequestId, RqRsMessage};
use futures::{channel::oneshot, future::BoxFuture, prelude::*, stream::FuturesUnordered};
use libp2p::{
    core::upgrade::{NegotiationError, UpgradeError},
    swarm::{ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive, SubstreamProtocol},
};
pub use protocol::{MessageProtocol, RequestProtocol, ResponseProtocol};
use smallvec::SmallVec;
use std::{
    collections::VecDeque,
    io,
    marker::PhantomData,
    sync::{atomic::AtomicU64, Arc},
    task::{Context, Poll},
    time::Duration,
};
use wasm_timer::Instant;

type ConnectionHandlerEventType<Rq, Rs> = ConnectionHandlerEvent<
    RequestProtocol<Rq, Rs>,
    RequestId,
    <Handler<Rq, Rs> as ConnectionHandler>::OutEvent,
    <Handler<Rq, Rs> as ConnectionHandler>::Error,
>;

type PendingInboundFuture<Rq, Rs> = BoxFuture<'static, Result<(RequestId, Rq, oneshot::Sender<Rs>), oneshot::Canceled>>;

// Events emitted in `NetBehaviour::poll` and injected to [`Handler::inject_event`].
#[derive(Debug)]
pub enum HandlerInEvent<Rq>
where
    Rq: RqRsMessage,
{
    // Send an outbound request.
    SendRequest { request_id: RequestId, request: Rq },
    // Set the protocol support for inbound and outbound requests.
    // This will be sent to the handler when the connection is first established,
    // and each time the effective firewall rule for the remote changes.
    SetInboundSupport(bool),
}

// Events emitted in [`Handler::poll`] and injected to `NetBehaviour::inject_event`.
#[derive(Debug)]
pub enum HandlerOutEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    // Received an inbound request from remote.
    ReceivedRequest {
        request_id: RequestId,
        request: Rq,
        response_tx: oneshot::Sender<Rs>,
    },
    // A response for an outbound request.
    ReceivedResponse {
        request_id: RequestId,
        response: Rs,
    },
    // A response for an inbound requests was successfully sent.
    SentResponse(RequestId),
    // The response channel closed from the sender side before a response was sent.
    SendResponseOmission(RequestId),
    // Timeout on sending a response.
    InboundTimeout(RequestId),
    // The inbound request was rejected because the local peer does not support any of the requested protocols.
    // This could be either because the protocols differ, or because the local firewall rejects all inbound requests.
    InboundUnsupportedProtocols(RequestId),
    // Timeout on receiving a response.
    OutboundTimeout(RequestId),
    // The outbound request was rejected because the remote peer does not support any of the requested protocols.
    // This could be either because the protocols differ, or because the remote firewall rejects all inbound requests.
    OutboundUnsupportedProtocols(RequestId),
}

// Handler for a single connection to a remote peer.
// One connection can have multiple substreams that each either negotiate the [`RequestProtocol`] or the
// [`ResponseProtocol`] by performing the respective handshake (send `Rq` - receive `Rs` | receive `Rq` - send `Rs`).
pub struct Handler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    // Protocol versions that are potentially supported.
    supported_protocols: SmallVec<[MessageProtocol; 2]>,
    // Whether inbound requests and thus the `ResponseProtocol` is supported.
    support_inbound: bool,
    // Timeout for negotiating a handshake on a substream i.g. sending a requests and receiving the response.
    request_timeout: Duration,
    // Timeout for an idle connection.
    keep_alive_timeout: Duration,

    // Current setting whether the connection to the remote should be kept alive.
    // This is set according to timeout configuration and pending requests.
    keep_alive: KeepAlive,
    // Request id assigned to the next inbound request.
    next_request_id: Arc<AtomicU64>,

    // Fatal error in connection.
    pending_error: Option<ConnectionHandlerUpgrErr<io::Error>>,

    // Pending events to emit to the `NetBehaviour`
    pending_events: VecDeque<HandlerOutEvent<Rq, Rs>>,
    // Pending outbound request that require a new [`ConnectionHandlerEvent::OutboundSubstreamRequest`].
    pending_out_req: VecDeque<(RequestId, Rq)>,
    // Pending inbound requests for which a [`ResponseProtocol`] was created, but no request message was received yet.
    pending_in_req: FuturesUnordered<PendingInboundFuture<Rq, Rs>>,
}

impl<Rq, Rs> Handler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    pub fn new(
        supported_protocols: SmallVec<[MessageProtocol; 2]>,
        support_inbound: bool,
        keep_alive_timeout: Duration,
        request_timeout: Duration,
        next_request_id: Arc<AtomicU64>,
    ) -> Self {
        Self {
            supported_protocols,
            support_inbound,
            request_timeout,
            keep_alive_timeout,
            keep_alive: KeepAlive::Yes,
            next_request_id,
            pending_error: None,
            pending_events: VecDeque::new(),
            pending_out_req: VecDeque::new(),
            pending_in_req: FuturesUnordered::new(),
        }
    }

    // Create a new [`RequestProtocol`] for an outbound request.
    fn new_outbound_protocol(
        &mut self,
        request_id: RequestId,
        request: Rq,
    ) -> SubstreamProtocol<RequestProtocol<Rq, Rs>, RequestId> {
        let proto = RequestProtocol {
            protocols: self.supported_protocols.clone(),
            request,
            _marker: PhantomData,
        };
        SubstreamProtocol::new(proto, request_id).with_timeout(self.request_timeout)
    }

    // Create a new [`ResponseProtocol`] for an inbound request.
    fn new_inbound_protocol(&self) -> SubstreamProtocol<ResponseProtocol<Rq, Rs>, RequestId> {
        // Assign a new request id to the expected request.
        let request_id = RequestId::next(&self.next_request_id);

        // Channel for the [`ResponseProtocol`] to forward the inbound request.
        let (request_tx, request_rx) = oneshot::channel();

        let protocols = self
            .support_inbound
            .then(|| self.supported_protocols.clone())
            .unwrap_or_default();

        let proto = ResponseProtocol { protocols, request_tx };

        self.pending_in_req.push(
            request_rx
                .map_ok(move |(request, tx)| (request_id, request, tx))
                .boxed(),
        );

        SubstreamProtocol::new(proto, request_id).with_timeout(self.request_timeout)
    }
}

impl<Rq, Rs> ConnectionHandler for Handler<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    type InEvent = HandlerInEvent<Rq>;
    type OutEvent = HandlerOutEvent<Rq, Rs>;
    type Error = ConnectionHandlerUpgrErr<io::Error>;
    type InboundProtocol = ResponseProtocol<Rq, Rs>;
    type OutboundProtocol = RequestProtocol<Rq, Rs>;
    type InboundOpenInfo = RequestId;
    type OutboundOpenInfo = RequestId;

    // Protocol and info for upgrading new inbound substreams.
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        self.new_inbound_protocol()
    }

    // Successfully received a requests and potentially sent a response.
    fn inject_fully_negotiated_inbound(&mut self, send_response: bool, request_id: RequestId) {
        let event = send_response
            .then(|| HandlerOutEvent::SentResponse(request_id))
            .unwrap_or(HandlerOutEvent::SendResponseOmission(request_id));
        self.pending_events.push_back(event);
    }

    // Successfully sent a requests and received a response.
    fn inject_fully_negotiated_outbound(&mut self, response: Rs, request_id: RequestId) {
        let event = HandlerOutEvent::ReceivedResponse { request_id, response };
        self.pending_events.push_back(event);
    }

    // New event emitted by the `NetBehaviour`.
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            HandlerInEvent::SendRequest { request_id, request } => {
                self.pending_out_req.push_back((request_id, request));
                self.keep_alive = KeepAlive::Yes;
            }
            HandlerInEvent::SetInboundSupport(b) => {
                self.support_inbound = b;
            }
        }
    }

    // Upgrading the outbound substream with the [`RequestProtocol`] failed.
    fn inject_dial_upgrade_error(&mut self, request_id: RequestId, error: ConnectionHandlerUpgrErr<io::Error>) {
        match error {
            ConnectionHandlerUpgrErr::Timeout => {
                self.pending_events
                    .push_back(HandlerOutEvent::OutboundTimeout(request_id));
            }
            ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                self.pending_events
                    .push_back(HandlerOutEvent::OutboundUnsupportedProtocols(request_id));
            }
            _ => {
                // Fatal error
                self.pending_error = Some(error);
            }
        }
    }

    // Upgrading the inbound substream with the [`ResponseProtocol`] failed.
    fn inject_listen_upgrade_error(&mut self, request_id: RequestId, error: ConnectionHandlerUpgrErr<io::Error>) {
        match error {
            ConnectionHandlerUpgrErr::Timeout => {
                self.pending_events
                    .push_back(HandlerOutEvent::InboundTimeout(request_id));
            }
            ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
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
        self.keep_alive
    }

    // Poll pending futures and emit events for requests, responses and errors.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEventType<Rq, Rs>> {
        // Check for fatal error.
        if let Some(err) = self.pending_error.take() {
            return Poll::Ready(ConnectionHandlerEvent::Close(err));
        }
        // Emit events to `NetBehaviour`.
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::Custom(event));
        }
        if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }
        // Forward inbound requests to `NetBehaviour` once the request was read from the substream.
        while let Poll::Ready(Some(result)) = self.pending_in_req.poll_next_unpin(cx) {
            if let Ok((request_id, request, response_tx)) = result {
                self.keep_alive = KeepAlive::Yes;
                return Poll::Ready(ConnectionHandlerEvent::Custom(HandlerOutEvent::ReceivedRequest {
                    request_id,
                    request,
                    response_tx,
                }));
            }
        }
        // Create new outbound substream with [`RequestProtocol`] for outbound requests.
        if let Some((request_id, request)) = self.pending_out_req.pop_front() {
            self.keep_alive = KeepAlive::Yes;
            let protocol = self.new_outbound_protocol(request_id, request);
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol });
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

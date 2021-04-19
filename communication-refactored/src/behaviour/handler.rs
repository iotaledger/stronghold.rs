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

use crate::behaviour::{RequestId, EMPTY_QUEUE_SHRINK_THRESHOLD};
use futures::{channel::oneshot, future::BoxFuture, prelude::*, stream::FuturesUnordered};
use libp2p::{
    core::upgrade::{NegotiationError, UpgradeError},
    swarm::{
        protocols_handler::{KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr},
        SubstreamProtocol,
    },
};
pub use protocol::{MessageEvent, MessageProtocol, ProtocolSupport, RequestProtocol, ResponseProtocol};
use smallvec::SmallVec;
use std::{
    collections::VecDeque,
    io,
    marker::PhantomData,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

type ProtocolsHandlerEventType<Req, Res> = ProtocolsHandlerEvent<
    RequestProtocol<Req, Res>,
    RequestId,
    <RequestResponseHandler<Req, Res> as ProtocolsHandler>::OutEvent,
    <RequestResponseHandler<Req, Res> as ProtocolsHandler>::Error,
>;

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerInEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    SendRequest { request_id: RequestId, request: Req },
    SendResponse { request_id: RequestId, response: Res },
}

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerOutEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    ReceiveRequest {
        request_id: RequestId,
        request: Req,
        sender: oneshot::Sender<Res>,
    },
    ReceiveResponse {
        request_id: RequestId,
        response: Res,
    },
    ResponseSent(RequestId),
    ResponseOmission(RequestId),
    OutboundTimeout(RequestId),
    OutboundUnsupportedProtocols(RequestId),
    InboundTimeout(RequestId),
    InboundUnsupportedProtocols(RequestId),
}

impl<Req, Res> HandlerOutEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub fn request_id(&self) -> &RequestId {
        match self {
            HandlerOutEvent::ReceiveRequest { request_id, .. }
            | HandlerOutEvent::ReceiveResponse { request_id, .. }
            | HandlerOutEvent::ResponseSent(request_id)
            | HandlerOutEvent::ResponseOmission(request_id)
            | HandlerOutEvent::OutboundTimeout(request_id)
            | HandlerOutEvent::OutboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id) => request_id,
        }
    }
}

type PendingInboundFuture<Req, Res> =
    BoxFuture<'static, Result<((RequestId, Req), oneshot::Sender<Res>), oneshot::Canceled>>;

#[doc(hidden)]
pub struct RequestResponseHandler<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    supported_protocols: SmallVec<[MessageProtocol; 2]>,
    protocol_support: ProtocolSupport,
    keep_alive_timeout: Duration,
    substream_timeout: Duration,
    keep_alive: KeepAlive,
    pending_error: Option<ProtocolsHandlerUpgrErr<io::Error>>,
    pending_events: VecDeque<HandlerOutEvent<Req, Res>>,
    outbound: VecDeque<(RequestId, Req)>,
    inbound: FuturesUnordered<PendingInboundFuture<Req, Res>>,
    inbound_request_id: Arc<AtomicU64>,
}

impl<Req, Res> RequestResponseHandler<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub(super) fn new(
        supported_protocols: SmallVec<[MessageProtocol; 2]>,
        protocol_support: ProtocolSupport,
        keep_alive_timeout: Duration,
        substream_timeout: Duration,
        inbound_request_id: Arc<AtomicU64>,
    ) -> Self {
        Self {
            supported_protocols,
            protocol_support,
            keep_alive: KeepAlive::Yes,
            keep_alive_timeout,
            substream_timeout,
            outbound: VecDeque::new(),
            inbound: FuturesUnordered::new(),
            pending_events: VecDeque::new(),
            pending_error: None,
            inbound_request_id,
        }
    }
}

impl<Req, Res> RequestResponseHandler<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    fn new_outbound_protocol(
        &mut self,
        request_id: RequestId,
        request: Req,
    ) -> SubstreamProtocol<RequestProtocol<Req, Res>, RequestId> {
        let proto = RequestProtocol {
            request_id,
            protocols: self.supported_protocols.clone(),
            request,
            marker: PhantomData,
        };
        SubstreamProtocol::new(proto, request_id).with_timeout(self.substream_timeout)
    }

    fn new_inbound_protocol(&self) -> SubstreamProtocol<ResponseProtocol<Req, Res>, RequestId> {
        let request_id = RequestId::new(self.inbound_request_id.fetch_add(1, Ordering::Relaxed));

        let (rq_send, rq_recv) = oneshot::channel();

        let (rs_send, rs_recv) = oneshot::channel();

        let protocols = self
            .protocol_support
            .inbound()
            .then(|| self.supported_protocols.clone())
            .unwrap_or_default();

        self.inbound.push(rq_recv.map_ok(move |rq| (rq, rs_send)).boxed());
        let proto = ResponseProtocol {
            protocols,
            request_sender: rq_send,
            response_receiver: rs_recv,
            request_id,
        };
        SubstreamProtocol::new(proto, request_id).with_timeout(self.substream_timeout)
    }
}

impl<Req, Res> ProtocolsHandler for RequestResponseHandler<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type InEvent = HandlerInEvent<Req, Res>;
    type OutEvent = HandlerOutEvent<Req, Res>;
    type Error = ProtocolsHandlerUpgrErr<io::Error>;
    type InboundProtocol = ResponseProtocol<Req, Res>;
    type OutboundProtocol = RequestProtocol<Req, Res>;
    type OutboundOpenInfo = RequestId;
    type InboundOpenInfo = RequestId;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        self.new_inbound_protocol()
    }

    fn inject_fully_negotiated_inbound(&mut self, sent: bool, request_id: RequestId) {
        if sent {
            self.pending_events.push_back(HandlerOutEvent::ResponseSent(request_id))
        } else {
            self.pending_events
                .push_back(HandlerOutEvent::ResponseOmission(request_id))
        }
    }

    fn inject_fully_negotiated_outbound(&mut self, response: Res, request_id: RequestId) {
        self.pending_events
            .push_back(HandlerOutEvent::ReceiveResponse { request_id, response });
    }

    fn inject_event(&mut self, request: Self::InEvent) {
        self.keep_alive = KeepAlive::Yes;
        if let HandlerInEvent::SendRequest { request_id, request } = request {
            self.outbound.push_back((request_id, request))
        }
    }

    fn inject_dial_upgrade_error(&mut self, info: RequestId, error: ProtocolsHandlerUpgrErr<io::Error>) {
        match error {
            ProtocolsHandlerUpgrErr::Timeout => {
                self.pending_events.push_back(HandlerOutEvent::OutboundTimeout(info));
            }
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                self.pending_events
                    .push_back(HandlerOutEvent::OutboundUnsupportedProtocols(info));
            }
            _ => {
                self.pending_error = Some(error);
            }
        }
    }

    fn inject_listen_upgrade_error(&mut self, info: RequestId, error: ProtocolsHandlerUpgrErr<io::Error>) {
        match error {
            ProtocolsHandlerUpgrErr::Timeout => self.pending_events.push_back(HandlerOutEvent::InboundTimeout(info)),
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                self.pending_events
                    .push_back(HandlerOutEvent::InboundUnsupportedProtocols(info));
            }
            _ => {
                self.pending_error = Some(error);
            }
        }
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ProtocolsHandlerEventType<Req, Res>> {
        if let Some(err) = self.pending_error.take() {
            return Poll::Ready(ProtocolsHandlerEvent::Close(err));
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ProtocolsHandlerEvent::Custom(event));
        }
        if self.pending_events.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.pending_events.shrink_to_fit();
        }

        while let Poll::Ready(Some(result)) = self.inbound.poll_next_unpin(cx) {
            match result {
                Ok(((id, rq), rs_sender)) => {
                    self.keep_alive = KeepAlive::Yes;
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(HandlerOutEvent::ReceiveRequest {
                        request_id: id,
                        request: rq,
                        sender: rs_sender,
                    }));
                }
                Err(oneshot::Canceled) => {}
            }
        }

        if let Some((request_id, request)) = self.outbound.pop_front() {
            let protocol = self.new_outbound_protocol(request_id, request);
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol });
        }

        if self.outbound.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.outbound.shrink_to_fit();
        }

        if self.inbound.is_empty() && self.keep_alive.is_yes() {
            let until = Instant::now() + self.substream_timeout + self.keep_alive_timeout;
            self.keep_alive = KeepAlive::Until(until);
        }

        Poll::Pending
    }
}

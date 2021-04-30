// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::channel::oneshot;
use libp2p::PeerId;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;

pub trait MessageEvent: Serialize + DeserializeOwned + Send + 'static {}
impl<T: Serialize + DeserializeOwned + Send + 'static> MessageEvent for T {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new(id: u64) -> Self {
        RequestId(id)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn inc(&mut self) -> &Self {
        self.0 += 1;
        self
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct Request<T, U> {
    pub message: T,
    pub response_sender: oneshot::Sender<U>,
}
#[derive(Debug)]
pub enum BehaviourEvent<Req, Res> {
    ReceiveRequest {
        peer: PeerId,
        request_id: RequestId,
        request: Request<Req, Res>,
    },
    ReceiveResponse {
        request_id: RequestId,
        peer: PeerId,
        result: Result<(), ReceiveResponseError>,
    },
}

#[derive(Debug, Clone)]
pub enum ReceiveResponseError {
    Timeout,
    DialFailure,
    ConnectionClosed,
    ReceiveResponseOmission,
    UnsupportedProtocols,
    NotPermitted,
}

impl fmt::Display for ReceiveResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiveResponseError::Timeout => write!(f, "Timeout while waiting for a response"),
            ReceiveResponseError::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            ReceiveResponseError::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            ReceiveResponseError::ReceiveResponseOmission => write!(
                f,
                "The response channel was dropped before receiving a response from the remote"
            ),
            ReceiveResponseError::NotPermitted => write!(f, "The firewall blocked the outbound request"),
            ReceiveResponseError::DialFailure => write!(f, "Failed to dial the requested peer"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReceiveRequestError {
    Timeout,
    UnsupportedProtocols,
    NotPermitted,
    ConnectionClosed,
}

impl fmt::Display for ReceiveRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiveRequestError::Timeout => write!(f, "Timeout while receiving request"),
            ReceiveRequestError::UnsupportedProtocols => write!(
                f,
                "The local peer supports none of the protocols requested by the remote"
            ),
            ReceiveRequestError::NotPermitted => write!(f, "The firewall blocked the inbound request"),
            ReceiveRequestError::ConnectionClosed => {
                write!(f, "The connection closed directly after the request was received")
            }
        }
    }
}

impl std::error::Error for ReceiveResponseError {}
impl std::error::Error for ReceiveRequestError {}

#[derive(Debug)]
pub struct ResponseReceiver<U> {
    peer: PeerId,
    request_id: RequestId,
    receiver: oneshot::Receiver<U>,
}

impl<U> ResponseReceiver<U> {
    pub fn new(peer: PeerId, request_id: RequestId, receiver: oneshot::Receiver<U>) -> Self {
        ResponseReceiver {
            request_id,
            peer,
            receiver,
        }
    }

    pub fn try_receive(&mut self) -> Result<Option<U>, oneshot::Canceled> {
        self.receiver.try_recv()
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}
#[doc(hidden)]
#[derive(Debug)]
pub struct HandlerInEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub(super) request_id: RequestId,
    pub(super) request: Request<Req, Res>,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerOutEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    ReceivedRequest {
        request_id: RequestId,
        request: Request<Req, Res>,
    },
    SentResponse(RequestId),
    SendResponseOmission(RequestId),
    InboundTimeout(RequestId),
    InboundUnsupportedProtocols(RequestId),

    ReceivedResponse(RequestId),
    ReceiveResponseOmission(RequestId),
    OutboundTimeout(RequestId),
    OutboundUnsupportedProtocols(RequestId),
}

impl<Req, Res> HandlerOutEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub fn request_id(&self) -> &RequestId {
        match self {
            HandlerOutEvent::ReceivedRequest { request_id, .. } => request_id,
            HandlerOutEvent::SentResponse(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id)
            | HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::ReceivedResponse(request_id)
            | HandlerOutEvent::ReceiveResponseOmission(request_id)
            | HandlerOutEvent::OutboundTimeout(request_id)
            | HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => request_id,
        }
    }
}

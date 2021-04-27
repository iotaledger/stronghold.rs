// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::channel::oneshot;
use libp2p::PeerId;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;

pub trait MessageEvent: Serialize + DeserializeOwned + Send + 'static {}
impl<T: Serialize + DeserializeOwned + Send + 'static> MessageEvent for T {}

#[derive(Debug)]
pub enum OutboundFailure {
    SendRequest(SendRequestError),
    ReceiveResponse(ReceiveResponseError),
}

pub enum Direction {
    Inbound,
    Outbound,
}

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

#[derive(Debug)]
pub struct Request<T, U> {
    pub message: T,
    pub request_id: RequestId,
    pub response_sender: oneshot::Sender<U>,
}

#[derive(Debug)]
pub struct BehaviourEvent<Req, Res> {
    pub request_id: RequestId,
    pub peer: PeerId,
    pub event: RequestResponseEvent<Req, Res>,
}

#[derive(Debug)]
pub enum RequestResponseEvent<Req, Res> {
    SendRequest(Result<(), SendRequestError>),
    ReceiveRequest(Result<Request<Req, Res>, ReceiveRequestError>),
    ReceiveResponse(Result<(), ReceiveResponseError>),
    SendResponse(Result<(), SendResponseError>),
}

#[derive(Debug, Clone)]
pub enum SendRequestError {
    Timeout,
    DialFailure,
    ConnectionClosed,
    UnsupportedProtocols,
    NotPermitted,
}

impl fmt::Display for SendRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SendRequestError::DialFailure => write!(f, "Failed to dial the requested peer"),
            SendRequestError::Timeout => write!(f, "Timeout while waiting for a response"),
            SendRequestError::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            SendRequestError::UnsupportedProtocols => write!(f, "The remote supports none of the requested protocols"),
            SendRequestError::NotPermitted => write!(f, "The request is not permitted"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReceiveResponseError {
    Timeout,
    ConnectionClosed,
    ReceiveResponseOmission,
}

impl fmt::Display for ReceiveResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiveResponseError::Timeout => write!(f, "Timeout while waiting for a response"),
            ReceiveResponseError::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            ReceiveResponseError::ReceiveResponseOmission => write!(
                f,
                "The response channel was dropped before receiving a response from the remote"
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReceiveRequestError {
    Timeout,
    UnsupportedProtocols,
}

impl fmt::Display for ReceiveRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiveRequestError::Timeout => write!(f, "Timeout while receiving request"),
            ReceiveRequestError::UnsupportedProtocols => write!(
                f,
                "The local peer supports none of the protocols requested by the remote"
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SendResponseError {
    Timeout,
    ConnectionClosed,
    SendResponseOmission,
}

impl fmt::Display for SendResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SendResponseError::Timeout => write!(f, "Timeout while sending response"),
            SendResponseError::ConnectionClosed => write!(f, "Connection was closed before a response could be sent"),
            SendResponseError::SendResponseOmission => write!(
                f,
                "The response channel was dropped without sending a response to the remote"
            ),
        }
    }
}

impl std::error::Error for SendRequestError {}
impl std::error::Error for ReceiveResponseError {}
impl std::error::Error for ReceiveRequestError {}
impl std::error::Error for SendResponseError {}

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

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerOutEvent<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    ReceivedRequest(Request<Req, Res>),
    ReceivedResponse(RequestId),
    SentResponse(RequestId),
    SentRequest(RequestId),
    SendResponseOmission(RequestId),
    ReceiveResponseOmission(RequestId),
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
            HandlerOutEvent::ReceivedRequest(request) => &request.request_id,
            HandlerOutEvent::ReceivedResponse(request_id)
            | HandlerOutEvent::ReceiveResponseOmission(request_id)
            | HandlerOutEvent::SentResponse(request_id)
            | HandlerOutEvent::SentRequest(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id)
            | HandlerOutEvent::OutboundTimeout(request_id)
            | HandlerOutEvent::OutboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id) => request_id,
        }
    }
}

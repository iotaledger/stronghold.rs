// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::channel::oneshot;
use libp2p::PeerId;
use std::fmt;

#[derive(Debug)]
pub struct Request<T, U> {
    pub message: T,
    pub response_channel: oneshot::Sender<U>,
}

#[derive(Debug)]
pub struct BehaviourEvent<Req, Res> {
    pub request_id: RequestId,
    pub peer_id: PeerId,
    pub event: RequestResponseEvent<Req, Res>,
}

#[derive(Debug)]
pub enum RequestResponseEvent<Req, Res> {
    SendRequest(Result<(), SendRequestError>),
    ReceiveResponse(Result<Res, ReceiveResponseError>),
    ReceiveRequest(Result<Request<Req, Res>, ReceiveRequestError>),
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
}

impl fmt::Display for ReceiveResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiveResponseError::Timeout => write!(f, "Timeout while waiting for a response"),
            ReceiveResponseError::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
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
    ResponseOmission,
}

impl fmt::Display for SendResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SendResponseError::Timeout => write!(f, "Timeout while sending response"),
            SendResponseError::ConnectionClosed => write!(f, "Connection was closed before a response could be sent"),
            SendResponseError::ResponseOmission => write!(
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

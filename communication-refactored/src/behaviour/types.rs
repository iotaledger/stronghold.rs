// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::firewall::FirewallRules;
use futures::channel::oneshot;
use libp2p::PeerId;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;

pub trait RqRsMessage: Serialize + DeserializeOwned + Send + Sync + 'static {}
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> RqRsMessage for T {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
pub struct Query<T, U> {
    pub data: T,
    pub response_tx: oneshot::Sender<U>,
}

pub type RequestMessage<Rq, Rs> = Query<Rq, Rs>;

#[derive(Debug)]
pub enum BehaviourEvent<Rq, Rs> {
    ReceiveRequest {
        peer: PeerId,
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    },
    ReceiveResponse {
        request_id: RequestId,
        peer: PeerId,
        result: Result<(), RecvResponseErr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvResponseErr {
    Timeout,
    DialFailure,
    ConnectionClosed,
    RecvResponseOmission,
    UnsupportedProtocols,
    NotPermitted,
    FirewallPermissionChannelClosed,
}

impl fmt::Display for RecvResponseErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecvResponseErr::Timeout => write!(f, "Timeout while waiting for a response"),
            RecvResponseErr::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            RecvResponseErr::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            RecvResponseErr::RecvResponseOmission => write!(
                f,
                "The response channel was dropped before receiving a response from the remote"
            ),
            RecvResponseErr::NotPermitted => write!(f, "The firewall blocked the outbound request"),
            RecvResponseErr::DialFailure => write!(f, "Failed to dial the requested peer"),
            RecvResponseErr::FirewallPermissionChannelClosed => {
                write!(f, "The channel to ask for permission for requests has closed.")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvRequestErr {
    Timeout,
    UnsupportedProtocols,
    NotPermitted,
    ConnectionClosed,
    FirewallPermissionChannelClosed,
}

impl fmt::Display for RecvRequestErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecvRequestErr::Timeout => write!(f, "Timeout while receiving request"),
            RecvRequestErr::UnsupportedProtocols => write!(
                f,
                "The local peer supports none of the protocols requested by the remote"
            ),
            RecvRequestErr::NotPermitted => write!(f, "The firewall blocked the inbound request"),
            RecvRequestErr::ConnectionClosed => {
                write!(f, "The connection closed directly after the request was received")
            }
            RecvRequestErr::FirewallPermissionChannelClosed => {
                write!(f, "The channel to ask for permission for requests has closed.")
            }
        }
    }
}

impl std::error::Error for RecvResponseErr {}
impl std::error::Error for RecvRequestErr {}

#[derive(Debug)]
pub struct ResponseReceiver<U> {
    pub peer: PeerId,
    pub request_id: RequestId,
    pub response_rx: oneshot::Receiver<U>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestDirection {
    Inbound,
    Outbound,
}

impl RequestDirection {
    pub fn is_inbound(&self) -> bool {
        matches!(self, RequestDirection::Inbound)
    }
    pub fn is_outbound(&self) -> bool {
        matches!(self, RequestDirection::Outbound)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerInEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    SendRequest {
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    },
    SetFirewallRules(FirewallRules),
}

#[doc(hidden)]
#[derive(Debug)]
pub enum HandlerOutEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    ReceivedRequest {
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
    },
    SentResponse(RequestId),
    SendResponseOmission(RequestId),
    InboundTimeout(RequestId),
    InboundUnsupportedProtocols(RequestId),

    ReceivedResponse(RequestId),
    RecvResponseOmission(RequestId),
    OutboundTimeout(RequestId),
    OutboundUnsupportedProtocols(RequestId),
}

impl<Rq, Rs> HandlerOutEvent<Rq, Rs>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
{
    pub fn request_id(&self) -> &RequestId {
        match self {
            HandlerOutEvent::ReceivedRequest { request_id, .. } => request_id,
            HandlerOutEvent::SentResponse(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id)
            | HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::ReceivedResponse(request_id)
            | HandlerOutEvent::RecvResponseOmission(request_id)
            | HandlerOutEvent::OutboundTimeout(request_id)
            | HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => request_id,
        }
    }
}

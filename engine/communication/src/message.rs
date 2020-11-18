// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::request_response::{InboundFailure, OutboundFailure, RequestResponseEvent, RequestResponseMessage};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mdns")]
use libp2p::mdns::MdnsEvent;

pub type Key = String;
pub type Value = String;
pub type ReqId = String;
pub type PeerStr = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxRecord {
    key: String,
    value: String,
}

impl MailboxRecord {
    pub fn new(key: Key, value: Key) -> Self {
        MailboxRecord { key, value }
    }

    pub fn key(&self) -> Key {
        self.key.clone()
    }
    pub fn value(&self) -> Value {
        self.value.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Ping,
    PutRecord(MailboxRecord),
    GetRecord(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Outcome(RequestOutcome),
    Record(MailboxRecord),
}

/// Indicates if a Request was received and / or the associated operation at the remote peer was successful
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestOutcome {
    Success,
    Error,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProcedureError {
    Outbound,
    Inbound,
    Other(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestResponseError {
    source: FailureSource,
    error: FailureType,
}

impl RequestResponseError {
    pub fn new(source: FailureSource, error: FailureType) -> Self {
        RequestResponseError { source, error }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FailureSource {
    Outbound,
    Inbound,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FailureType {
    DialFailure,
    Timeout,
    ConnectionClosed,
    UnsupportedProtocols,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CommunicationEvent {
    Mdns,
    RequestMessage {
        peer: PeerStr,
        request_id: ReqId,
        request: Request,
    },
    ResponseMessage {
        peer: PeerStr,
        request_id: ReqId,
        response: Response,
    },
    RequestResponseError {
        peer: PeerStr,
        request_id: ReqId,
        error: RequestResponseError,
    },
}

#[cfg(feature = "mdns")]
impl From<MdnsEvent> for CommunicationEvent {
    fn from(_: MdnsEvent) -> CommunicationEvent {
        CommunicationEvent::Mdns
    }
}

impl From<RequestResponseEvent<Request, Response>> for CommunicationEvent {
    fn from(event: RequestResponseEvent<Request, Response>) -> CommunicationEvent {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel: _,
                } => CommunicationEvent::RequestMessage {
                    peer: peer.to_string(),
                    request_id: request_id.to_string(),
                    request,
                },
                RequestResponseMessage::Response { request_id, response } => CommunicationEvent::ResponseMessage {
                    peer: peer.to_string(),
                    request_id: request_id.to_string(),
                    response,
                },
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                let error = match error {
                    OutboundFailure::DialFailure => FailureType::DialFailure,
                    OutboundFailure::Timeout => FailureType::Timeout,
                    OutboundFailure::ConnectionClosed => FailureType::ConnectionClosed,
                    OutboundFailure::UnsupportedProtocols => FailureType::UnsupportedProtocols,
                };
                CommunicationEvent::RequestResponseError {
                    peer: peer.to_string(),
                    request_id: request_id.to_string(),
                    error: RequestResponseError {
                        source: FailureSource::Outbound,
                        error,
                    },
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                let error = match error {
                    InboundFailure::Timeout => FailureType::Timeout,
                    InboundFailure::ConnectionClosed => FailureType::ConnectionClosed,
                    InboundFailure::UnsupportedProtocols => FailureType::UnsupportedProtocols,
                };
                CommunicationEvent::RequestResponseError {
                    peer: peer.to_string(),
                    request_id: request_id.to_string(),
                    error: RequestResponseError {
                        source: FailureSource::Inbound,
                        error,
                    },
                }
            }
        }
    }
}

#[test]
fn test_new_message() {
    let key = String::from("key1");
    let value = String::from("value1");
    let record = MailboxRecord::new(key.clone(), value.clone());
    assert_eq!(record.key(), key);
    assert_eq!(record.value(), value);
}

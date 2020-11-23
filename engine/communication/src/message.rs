// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::{
    core::{Multiaddr, PeerId},
    identify::IdentifyEvent,
    identity::PublicKey,
    request_response::{InboundFailure, OutboundFailure, RequestId, RequestResponseEvent, RequestResponseMessage},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mdns")]
use libp2p::mdns::MdnsEvent;

pub type Key = String;
pub type Value = String;

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

#[derive(Debug, Clone)]
pub enum ReqResEvent {
    Req(Request),
    Res(Response),
    ReqResErr(RequestResponseError),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CommunicationEvent {
    SwarmCtrl,
    Identify {
        peer_id: PeerId,
        public_key: PublicKey,
        observed_addr: Multiaddr,
    },
    RequestResponse {
        peer_id: PeerId,
        request_id: RequestId,
        event: ReqResEvent,
    },
}

#[cfg(feature = "mdns")]
impl From<MdnsEvent> for CommunicationEvent {
    fn from(_event: MdnsEvent) -> CommunicationEvent {
        CommunicationEvent::SwarmCtrl
    }
}

impl From<IdentifyEvent> for CommunicationEvent {
    fn from(event: IdentifyEvent) -> CommunicationEvent {
        if let IdentifyEvent::Received {
            peer_id,
            info,
            observed_addr,
        } = event
        {
            CommunicationEvent::Identify {
                peer_id,
                public_key: info.public_key,
                observed_addr,
            }
        } else {
            CommunicationEvent::SwarmCtrl
        }
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
                } => CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: ReqResEvent::Req(request),
                },
                RequestResponseMessage::Response { request_id, response } => CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: ReqResEvent::Res(response),
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
                CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: ReqResEvent::ReqResErr(RequestResponseError {
                        source: FailureSource::Outbound,
                        error,
                    }),
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
                CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: ReqResEvent::ReqResErr(RequestResponseError {
                        source: FailureSource::Inbound,
                        error,
                    }),
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

// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use libp2p::request_response::{InboundFailure, OutboundFailure, RequestResponseEvent, RequestResponseMessage};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mdns")]
use libp2p::mdns::MdnsEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxRecord {
    key: String,
    value: String,
    expires_sec: u64,
}

impl MailboxRecord {
    pub fn new(key: String, value: String, expires_sec: u64) -> Self {
        MailboxRecord {
            key,
            value,
            expires_sec,
        }
    }

    pub fn key(&self) -> String {
        self.key.clone()
    }
    pub fn value(&self) -> String {
        self.value.clone()
    }
    pub fn expires_sec(&self) -> u64 {
        self.expires_sec
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

pub type PeerString = String;
pub type RequestString = String;
pub type Key = String;
pub type Value = String;

#[derive(Serialize, Deserialize, Debug)]
pub enum ProcedureError {
    Outbound,
    Inbound,
    Other(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestResponseError {
    source: FailureSource,
    error: FailureType,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FailureSource {
    Outbound,
    Inbound,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FailureType {
    DialFailure,
    Timeout,
    ConnectionClosed,
    UnsupportedProtocols,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CommunicationEvent {
    Shutdown,
    MdnsEvent,
    RequestMessage {
        originating_peer: PeerString,
        id: RequestString,
        procedure: Request,
    },
    ResponseMessage {
        id: RequestString,
        outcome: Result<Response, ProcedureError>,
    },
    RequestResponseError {
        peer: PeerString,
        request_id: RequestString,
        error: RequestResponseError,
    },
    StartListening,
    StopListening,
}

#[cfg(feature = "mdns")]
impl From<MdnsEvent> for CommunicationEvent {
    fn from(_: MdnsEvent) -> CommunicationEvent {
        CommunicationEvent::MdnsEvent
    }
}

impl From<RequestResponseEvent<Request, Response>> for CommunicationEvent {
    fn from(other: RequestResponseEvent<Request, Response>) -> CommunicationEvent {
        match other {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel: _,
                } => CommunicationEvent::RequestMessage {
                    originating_peer: peer.to_string(),
                    id: request_id.to_string(),
                    procedure: request,
                },
                RequestResponseMessage::Response { request_id, response } => CommunicationEvent::ResponseMessage {
                    id: request_id.to_string(),
                    outcome: Ok(response),
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
    let expires = 1000u64;
    let record = MailboxRecord::new(key.clone(), value.clone(), expires);
    assert_eq!(record.key(), key);
    assert_eq!(record.value(), value);
    assert_eq!(record.expires_sec(), expires);
}

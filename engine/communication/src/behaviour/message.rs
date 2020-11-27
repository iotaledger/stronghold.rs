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
pub enum ReqResEvent<T, U> {
    Req(T),
    Res(U),
    ReqResErr(RequestResponseError),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CommunicationEvent<T, U> {
    SwarmCtrl,
    Identify {
        peer_id: PeerId,
        public_key: PublicKey,
        observed_addr: Multiaddr,
    },
    RequestResponse {
        peer_id: PeerId,
        request_id: RequestId,
        event: ReqResEvent<T, U>,
    },
}

#[cfg(feature = "mdns")]
impl<T, U> From<MdnsEvent> for CommunicationEvent<T, U> {
    fn from(_event: MdnsEvent) -> CommunicationEvent<T, U> {
        CommunicationEvent::SwarmCtrl
    }
}

impl<T, U> From<IdentifyEvent> for CommunicationEvent<T, U> {
    fn from(event: IdentifyEvent) -> CommunicationEvent<T, U> {
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

impl<T, U> From<RequestResponseEvent<T, U>> for CommunicationEvent<T, U> {
    fn from(event: RequestResponseEvent<T, U>) -> CommunicationEvent<T, U> {
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

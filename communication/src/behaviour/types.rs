// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use libp2p::{
    core::{Multiaddr, PeerId},
    identify::{IdentifyEvent, IdentifyInfo},
    identity::PublicKey,
    request_response::{InboundFailure, OutboundFailure, RequestId, RequestResponseEvent, RequestResponseMessage},
    swarm::ProtocolsHandlerUpgrErr,
};

#[cfg(feature = "mdns")]
use libp2p::mdns::MdnsEvent;

/// Event that can be produced by the `Mdns` behaviour.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PMdnsEvent {
    /// Discovered nodes through mDNS.
    Discovered(Vec<(PeerId, Multiaddr)>),
    /// Each discovered record has a time-to-live. When this TTL expires and the address hasn't
    /// been refreshed, it is removed from the list and emit it as an `Expired` event.
    Expired(Vec<(PeerId, Multiaddr)>),
}

/// Information of a peer sent in `Identify` protocol responses.
#[derive(Debug, Clone, PartialEq)]
pub struct P2PIdentifyInfo {
    /// The public key underlying the peer's `PeerId`.
    pub public_key: PublicKey,
    /// Version of the protocol family used by the peer, e.g. `p2p/1.0.0`
    pub protocol_version: String,
    /// Name and version of the peer, similar to the `User-Agent` header in
    /// the HTTP protocol.
    pub agent_version: String,
    /// The addresses that the peer is listening on.
    pub listen_addrs: Vec<Multiaddr>,
    /// The list of protocols supported by the peer, e.g. `/p2p/ping/1.0.0`.
    pub protocols: Vec<String>,
    /// The address observed by the peer for the local node.
    pub observed_addr: Multiaddr,
}

/// Error that can happen on an outbound substream opening attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PProtocolsHandlerUpgrErr {
    /// The opening attempt timed out before the negotiation was fully completed.
    Timeout,
    /// There was an error in the timer used.
    Timer,
    /// Error while upgrading the substream to the protocol we want.
    Upgrade,
}

/// Event emitted  by the `Identify` behaviour.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PIdentifyEvent {
    /// Identifying information has been received from a peer.
    Received { peer_id: PeerId, info: P2PIdentifyInfo },
    /// Identifying information of the local node has been sent to a peer.
    Sent { peer_id: PeerId },
    /// Identification information of the local node has been actively pushed to
    /// a peer.
    Pushed {
        /// The peer that the information has been sent to.
        peer_id: PeerId,
    },
    /// Error while attempting to identify the remote.
    Error {
        peer_id: PeerId,
        error: P2PProtocolsHandlerUpgrErr,
    },
}
/// Possible failures occurring in the context of sending
/// an outbound request and receiving the response.
#[derive(Debug, Clone, PartialEq)]
pub enum P2POutboundFailure {
    /// The request could not be sent because a dialing attempt failed.
    DialFailure,
    /// The request timed out before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    Timeout,
    /// The connection closed before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    ConnectionClosed,
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
}

/// Possible failures occurring in the context of receiving an
/// inbound request and sending a response.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PInboundFailure {
    /// The inbound request timed out, either while reading the
    /// incoming request or before a response is sent
    Timeout,
    /// The local peer supports none of the requested protocols.
    UnsupportedProtocols,
    /// The local peer failed to respond to an inbound request
    /// due to the [`ResponseChannel`] being dropped instead of
    /// being passed to [`RequestResponse::send_response`].
    ResponseOmission,
    /// The connection closed before a response could be send.
    ConnectionClosed,
}

/// Event emitted  by the `RequestResponse` behaviour.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PReqResEvent<Req, Res> {
    /// Request Message
    ///
    /// Requests require a response to acknowledge them, if [`P2PNetworkBehaviour::send_response`]
    /// is not called in a timely manner, the protocol issues an
    /// `InboundFailure` at the local node and an `OutboundFailure` at the remote.
    Req {
        peer_id: PeerId,
        request_id: RequestId,
        request: Req,
    },
    /// Response Message to a received `Req`.
    ///
    /// The `ResponseChannel` for the request is stored by the `P2PNetworkBehaviour` in
    /// a Hashmap and identified by the  `request_id` that can be used to send the response.
    /// If the `ResponseChannel` for the `request_id`is already closed
    /// due to a timeout, the response is discarded and eventually
    /// [`RequestResponseEvent::InboundFailure`] is emitted.
    Res {
        peer_id: PeerId,
        request_id: RequestId,
        response: Res,
    },
    InboundFailure {
        peer_id: PeerId,
        request_id: RequestId,
        error: P2PInboundFailure,
    },
    OutboundFailure {
        peer_id: PeerId,
        request_id: RequestId,
        error: P2POutboundFailure,
    },
    /// A response to an inbound request has been sent.
    ///
    /// When this event is received, the response has been flushed on the underlying transport connection.
    ResSent { peer_id: PeerId, request_id: RequestId },
}

/// Event that was emitted by one of the protocols of the `P2PNetworkBehaviour`
#[derive(Debug, Clone, PartialEq)]
pub enum P2PEvent<Req, Res> {
    /// Events from the libp2p mDNS protocol
    Mdns(P2PMdnsEvent),
    /// Events from the libp2p identify protocol
    Identify(Box<P2PIdentifyEvent>),
    /// Events from the custom request-response protocol
    RequestResponse(Box<P2PReqResEvent<Req, Res>>),
}

#[cfg(feature = "mdns")]
impl<Req, Res> From<MdnsEvent> for P2PEvent<Req, Res> {
    fn from(event: MdnsEvent) -> P2PEvent<Req, Res> {
        match event {
            MdnsEvent::Discovered(list) => P2PEvent::Mdns(P2PMdnsEvent::Discovered(list.collect())),
            MdnsEvent::Expired(list) => P2PEvent::Mdns(P2PMdnsEvent::Expired(list.collect())),
        }
    }
}

impl<Req, Res> From<IdentifyEvent> for P2PEvent<Req, Res> {
    fn from(event: IdentifyEvent) -> P2PEvent<Req, Res> {
        match event {
            IdentifyEvent::Received {
                peer_id,
                info:
                    IdentifyInfo {
                        public_key,
                        protocol_version,
                        agent_version,
                        listen_addrs,
                        protocols,
                        observed_addr,
                    },
            } => P2PEvent::Identify(Box::new(P2PIdentifyEvent::Received {
                peer_id,
                info: P2PIdentifyInfo {
                    public_key,
                    protocol_version,
                    agent_version,
                    listen_addrs,
                    protocols,
                    observed_addr,
                },
            })),
            IdentifyEvent::Sent { peer_id } => P2PEvent::Identify(Box::new(P2PIdentifyEvent::Sent { peer_id })),
            IdentifyEvent::Pushed { peer_id } => P2PEvent::Identify(Box::new(P2PIdentifyEvent::Pushed { peer_id })),
            IdentifyEvent::Error { peer_id, error } => {
                let error = match error {
                    ProtocolsHandlerUpgrErr::Timeout => P2PProtocolsHandlerUpgrErr::Timeout,
                    ProtocolsHandlerUpgrErr::Timer => P2PProtocolsHandlerUpgrErr::Timer,
                    ProtocolsHandlerUpgrErr::Upgrade(_) => P2PProtocolsHandlerUpgrErr::Upgrade,
                };
                P2PEvent::Identify(Box::new(P2PIdentifyEvent::Error { peer_id, error }))
            }
        }
    }
}

impl<Req, Res> From<RequestResponseEvent<Req, Res>> for P2PEvent<Req, Res> {
    fn from(event: RequestResponseEvent<Req, Res>) -> P2PEvent<Req, Res> {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id, request, ..
                } => P2PEvent::RequestResponse(Box::new(P2PReqResEvent::Req {
                    peer_id: peer,
                    request_id,
                    request,
                })),
                RequestResponseMessage::Response { request_id, response } => {
                    P2PEvent::RequestResponse(Box::new(P2PReqResEvent::Res {
                        peer_id: peer,
                        request_id,
                        response,
                    }))
                }
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                let error = match error {
                    OutboundFailure::DialFailure => P2POutboundFailure::DialFailure,
                    OutboundFailure::Timeout => P2POutboundFailure::Timeout,
                    OutboundFailure::ConnectionClosed => P2POutboundFailure::ConnectionClosed,
                    OutboundFailure::UnsupportedProtocols => P2POutboundFailure::UnsupportedProtocols,
                };
                P2PEvent::RequestResponse(Box::new(P2PReqResEvent::OutboundFailure {
                    peer_id: peer,
                    request_id,
                    error,
                }))
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                let error = match error {
                    InboundFailure::Timeout => P2PInboundFailure::Timeout,
                    InboundFailure::ResponseOmission => P2PInboundFailure::ResponseOmission,
                    InboundFailure::UnsupportedProtocols => P2PInboundFailure::UnsupportedProtocols,
                    InboundFailure::ConnectionClosed => P2PInboundFailure::ConnectionClosed,
                };
                P2PEvent::RequestResponse(Box::new(P2PReqResEvent::InboundFailure {
                    peer_id: peer,
                    request_id,
                    error,
                }))
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                P2PEvent::RequestResponse(Box::new(P2PReqResEvent::ResSent {
                    peer_id: peer,
                    request_id,
                }))
            }
        }
    }
}

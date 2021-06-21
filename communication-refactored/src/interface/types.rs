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

use crate::{behaviour::BehaviourEvent, ConnectionErr};
use futures::channel::oneshot;
use libp2p::{
    core::connection::{ConnectedPoint, ConnectionError},
    swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::SmallVec;
use std::{convert::TryFrom, fmt, io, num::NonZeroU32};

/// Trait for the generic Request and Response messages.
pub trait RqRsMessage: Serialize + DeserializeOwned + Send + Sync + 'static {}
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> RqRsMessage for T {}

/// Unique Id for each Request.
/// **Note**: This Id is only local and does not match the request's ID at the remote peer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    pub(crate) fn new(id: u64) -> Self {
        RequestId(id)
    }

    pub(crate) fn value(&self) -> u64 {
        self.0
    }

    pub(crate) fn inc(&mut self) -> &Self {
        self.0 += 1;
        self
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generic data structure that provides some information and expects a response to be returned.
/// This is used for e.g. permission requests to the firewall, and for receiving requests and responding to them.
#[derive(Debug)]
pub struct Query<T, U> {
    /// Content or data of the message.
    pub data: T,
    /// Chanel for sending the response.
    pub response_tx: oneshot::Sender<U>,
}

/// Request from / to a remote peer, for which a response is expected.
pub type RequestMessage<Rq, Rs> = Query<Rq, Rs>;

/// Inbound Request from a remote peer.
#[derive(Debug)]
pub struct ReceiveRequest<Rq, Rs> {
    /// ID of the remote peer that send the request.
    pub peer: PeerId,
    /// ID of the request.
    pub request_id: RequestId,
    /// Request content and response channel.
    pub request: RequestMessage<Rq, Rs>,
}

/// Data structure for receiving the response for an outbound requests.
#[derive(Debug)]
pub struct ResponseReceiver<U> {
    /// ID of the remote peer to whom the requests was send.
    pub peer: PeerId,
    /// ID of the request.
    pub request_id: RequestId,
    /// Channel for receiving the response from remote.
    /// In case of an error, this channel will be dropped from the sender side, and an
    /// [`NetworkEvent::OutboundFailure`] may be emitted from [`ShCommunication`].
    pub response_rx: oneshot::Receiver<U>,
}

/// Active Listener of the local peer.
pub struct Listener {
    /// The addresses associated with this listener.
    pub addrs: SmallVec<[Multiaddr; 6]>,
    /// Whether the listener uses a relay.
    pub uses_relay: Option<PeerId>,
}

/// Direction of a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestDirection {
    /// Inbound requests sent from a remote peer.
    Inbound,
    /// Outbound requests sent to a remote peer.
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

/// Events happening in the Network.
/// Includes events about connection and listener status as well as potential failures when sending/ receiving
/// request-response messages.
#[derive(Debug)]
pub enum NetworkEvent {
    ///
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    OutboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: OutboundFailure,
    },
    /// A connection to the given peer has been opened.
    ConnectionEstablished {
        /// Identity of the peer that connected.
        peer: PeerId,
        /// Endpoint of the connection that has been opened.
        endpoint: ConnectedPoint,
        /// Number of established connections to this peer, including the one that has just been
        /// opened.
        num_established: NonZeroU32,
    },
    /// A connection with the given peer has been closed,
    /// possibly as a result of an error.
    ConnectionClosed {
        /// Identity of the peer that disconnected.
        peer: PeerId,
        /// Endpoint of the connection that has been closed.
        endpoint: ConnectedPoint,
        /// Number of other remaining connections to this same peer.
        num_established: u32,
        /// Potential Error that resulted in the disconnection.
        cause: Option<io::Error>,
    },
    /// An error happened on a connection during its initial handshake.
    ///
    /// This can include, for example, an error during the handshake of the encryption layer, or
    /// the connection unexpectedly closed.
    IncomingConnectionError {
        /// Local connection address.
        /// This address has been earlier reported with a [`NewListenAddr`](SwarmEvent::NewListenAddr)
        /// event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
        /// The error that happened.
        error: ConnectionErr,
    },
    /// One of the listeners has reported a new local listening address.
    NewListenAddr(Multiaddr),
    /// One of the listeners has reported the expiration of a listening address.
    ExpiredListenAddr(Multiaddr),
    /// One of the listeners gracefully closed.
    ListenerClosed {
        /// The addresses that the listener was listening on. These addresses are now considered
        /// expired, similar to if a [`ExpiredListenAddr`](SwarmEvent::ExpiredListenAddr) event
        /// has been generated for each of them.
        addresses: Vec<Multiaddr>,
        /// Potential Error in the stream that cause the listener to close.
        cause: Option<io::Error>,
    },
    /// One of the listeners reported a non-fatal error.
    ListenerError {
        /// The listener error.
        error: io::Error,
    },
}

pub(crate) type SwarmEv<Rq, Rs, THandleErr> = SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>;

impl<Rq: RqRsMessage, Rs: RqRsMessage, THandleErr> TryFrom<SwarmEv<Rq, Rs, THandleErr>> for NetworkEvent {
    type Error = ();
    fn try_from(value: SwarmEv<Rq, Rs, THandleErr>) -> Result<Self, Self::Error> {
        match value {
            SwarmEvent::Behaviour(ev) => match ev {
                BehaviourEvent::Request(_) => Err(()),
                BehaviourEvent::OutboundFailure {
                    request_id,
                    peer,
                    failure,
                } => Ok(NetworkEvent::OutboundFailure {
                    request_id,
                    peer,
                    failure,
                }),
                BehaviourEvent::InboundFailure {
                    request_id,
                    peer,
                    failure,
                } => Ok(NetworkEvent::InboundFailure {
                    request_id,
                    peer,
                    failure,
                }),
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
            } => Ok(NetworkEvent::ConnectionEstablished {
                peer: peer_id,
                num_established,
                endpoint,
            }),
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
            } => {
                let cause = match cause {
                    Some(ConnectionError::IO(e)) => Some(e),
                    _ => None,
                };
                Ok(NetworkEvent::ConnectionClosed {
                    peer: peer_id,
                    num_established,
                    endpoint,
                    cause,
                })
            }
            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
            } => Ok(NetworkEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error: error.into(),
            }),
            SwarmEvent::ExpiredListenAddr(addr) => Ok(NetworkEvent::ExpiredListenAddr(addr)),
            SwarmEvent::ListenerClosed { addresses, reason } => {
                let cause = match reason {
                    Ok(()) => None,
                    Err(e) => Some(e),
                };
                Ok(NetworkEvent::ListenerClosed { addresses, cause })
            }
            SwarmEvent::ListenerError { error } => Ok(NetworkEvent::ListenerError { error }),
            SwarmEvent::NewListenAddr(addr) => Ok(NetworkEvent::NewListenAddr(addr)),
            _ => Err(()),
        }
    }
}

impl std::error::Error for InboundFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundFailure {
    /// The request timed out before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    Timeout,
    /// The request could not be sent because a dialing attempt failed.
    DialFailure,
    /// The connection closed before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    ConnectionClosed,
    /// The Receiver side of the response channel was dropped before the response from remote could be forwarded.
    RecvResponseOmission,
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
    /// The local firewall blocked the request.
    NotPermitted,
}

impl fmt::Display for OutboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OutboundFailure::Timeout => write!(f, "Timeout while waiting for a response"),
            OutboundFailure::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            OutboundFailure::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            OutboundFailure::RecvResponseOmission => write!(
                f,
                "The response channel was dropped before receiving a response from the remote"
            ),
            OutboundFailure::NotPermitted => write!(f, "The firewall blocked the outbound request"),
            OutboundFailure::DialFailure => write!(f, "Failed to dial the requested peer"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundFailure {
    /// The inbound request timed out, either while reading the
    /// incoming request or before a response is sent through [`RequestMessage.response_tx`].
    Timeout,
    /// The local firewall blocked the request.
    NotPermitted,
    /// The connection closed before a response could be send.
    ConnectionClosed,
}

impl fmt::Display for InboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InboundFailure::Timeout => write!(f, "Timeout while receiving request"),
            InboundFailure::NotPermitted => write!(f, "The firewall blocked the inbound request"),
            InboundFailure::ConnectionClosed => {
                write!(f, "The connection closed directly after the request was received")
            }
        }
    }
}

impl std::error::Error for OutboundFailure {}

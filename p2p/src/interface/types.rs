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
    core::connection::ConnectedPoint,
    swarm::{ConnectionError, ConnectionLimits as Libp2pConnectionLimits, SwarmEvent},
    Multiaddr, PeerId,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use smallvec::SmallVec;
use std::{fmt, io, num::NonZeroU32};

/// Trait for the generic request and response messages.
pub trait RqRsMessage: Serialize + DeserializeOwned + Send + Sync + fmt::Debug + 'static {}
impl<TRq: Serialize + DeserializeOwned + Send + Sync + fmt::Debug + 'static> RqRsMessage for TRq {}

/// Unique Id for each request.
/// **Note**: This ID is only local and does not match the request's ID at the remote peer.
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

/// Inbound Request from a remote peer.
/// It is expected that a response will be returned through the `response_rx` channel,
/// otherwise an [`OutboundFailure`] will occur at the remote peer.
#[derive(Debug)]
pub struct ReceiveRequest<Rq, Rs> {
    /// ID of the request.
    pub request_id: RequestId,
    /// ID of the remote peer that send the request.
    pub peer: PeerId,
    /// Request from the remote peer.
    pub request: Rq,
    /// Channel for returning the response.
    ///
    /// **Note:** If an [`InboundFailure`] occurs before a response was sent, the Receiver side of this channel is
    /// dropped.
    pub response_tx: oneshot::Sender<Rs>,
}

/// Active Listener of the local peer.
#[derive(Debug, Clone)]
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

/// Events happening in the Network.
/// Includes events about connection and listener status as well as potential failures when receiving
/// request-response messages.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A failure occurred in the context of receiving an inbound request and sending a response.
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
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

type SwarmEv<Rq, Rs, THandleErr> = SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>;

impl<Rq: RqRsMessage, Rs: RqRsMessage, THandleErr> TryFrom<SwarmEv<Rq, Rs, THandleErr>> for NetworkEvent {
    type Error = ();
    fn try_from(value: SwarmEv<Rq, Rs, THandleErr>) -> Result<Self, Self::Error> {
        match value {
            SwarmEvent::Behaviour(BehaviourEvent::InboundFailure {
                request_id,
                peer,
                failure,
            }) => Ok(NetworkEvent::InboundFailure {
                request_id,
                peer,
                failure,
            }),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                concurrent_dial_errors: _,
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
            SwarmEvent::ExpiredListenAddr { address, .. } => Ok(NetworkEvent::ExpiredListenAddr(address)),
            SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                let cause = match reason {
                    Ok(()) => None,
                    Err(e) => Some(e),
                };
                Ok(NetworkEvent::ListenerClosed { addresses, cause })
            }
            SwarmEvent::ListenerError { error, .. } => Ok(NetworkEvent::ListenerError { error }),
            SwarmEvent::NewListenAddr { address, .. } => Ok(NetworkEvent::NewListenAddr(address)),
            _ => Err(()),
        }
    }
}

impl std::error::Error for InboundFailure {}

/// Possible failures occurring in the context of sending an outbound request and receiving the response.
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
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
    /// The local firewall blocked the request.
    NotPermitted,
    /// `StrongholdP2p` was shut down before a response was received.
    Shutdown,
}

impl fmt::Display for OutboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OutboundFailure::Timeout => write!(f, "Timeout while waiting for a response"),
            OutboundFailure::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            OutboundFailure::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            OutboundFailure::NotPermitted => write!(f, "The firewall blocked the outbound request"),
            OutboundFailure::DialFailure => write!(f, "Failed to dial the requested peer"),
            OutboundFailure::Shutdown => write!(f, "The local peer was shut down before a response was received."),
        }
    }
}

/// Possible failures occurring in the context of receiving an inbound request and sending a response.
///
/// **Note**: If the firewall is configured to block per se all requests from the remote peer, the protocol for inbound
/// requests will not be supported in the first place, and inbound requests are rejected without emitting a failure.
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionLimits {
    max_pending_incoming: Option<u32>,
    max_pending_outgoing: Option<u32>,
    max_established_incoming: Option<u32>,
    max_established_outgoing: Option<u32>,
    max_established_per_peer: Option<u32>,
    max_established_total: Option<u32>,
}

impl From<ConnectionLimits> for Libp2pConnectionLimits {
    fn from(l: ConnectionLimits) -> Self {
        Libp2pConnectionLimits::default()
            .with_max_pending_incoming(l.max_pending_incoming)
            .with_max_pending_outgoing(l.max_pending_outgoing)
            .with_max_established_incoming(l.max_established_incoming)
            .with_max_established_outgoing(l.max_established_outgoing)
            .with_max_established_per_peer(l.max_established_per_peer)
            .with_max_established(l.max_established_total)
    }
}

impl ConnectionLimits {
    /// Configures the maximum number of concurrently incoming connections being established.
    pub fn with_max_pending_incoming(mut self, limit: Option<u32>) -> Self {
        self.max_pending_incoming = limit;
        self
    }

    /// Configures the maximum number of concurrently outgoing connections being established.
    pub fn with_max_pending_outgoing(mut self, limit: Option<u32>) -> Self {
        self.max_pending_outgoing = limit;
        self
    }

    /// Configures the maximum number of concurrent established inbound connections.
    pub fn with_max_established_incoming(mut self, limit: Option<u32>) -> Self {
        self.max_established_incoming = limit;
        self
    }

    /// Configures the maximum number of concurrent established outbound connections.
    pub fn with_max_established_outgoing(mut self, limit: Option<u32>) -> Self {
        self.max_established_outgoing = limit;
        self
    }

    /// Configures the maximum number of concurrent established connections (both
    /// inbound and outbound).
    ///
    /// Note: This should be used in conjunction with
    /// [`ConnectionLimits::with_max_established_incoming`] to prevent possible
    /// eclipse attacks (all connections being inbound).
    pub fn with_max_established(mut self, limit: Option<u32>) -> Self {
        self.max_established_total = limit;
        self
    }

    /// Configures the maximum number of concurrent established connections per peer,
    /// regardless of direction (incoming or outgoing).
    pub fn with_max_established_per_peer(mut self, limit: Option<u32>) -> Self {
        self.max_established_per_peer = limit;
        self
    }
}

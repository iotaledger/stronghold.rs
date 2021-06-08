// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::channel::oneshot;
use libp2p::{
    core::connection::{ConnectedPoint, ConnectionError, ConnectionLimit, PendingConnectionError},
    swarm::SwarmEvent,
    Multiaddr, PeerId, TransportError,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{convert::TryFrom, fmt, io, num::NonZeroU32};

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
pub struct ReceiveRequest<Rq, Rs> {
    pub peer: PeerId,
    pub request_id: RequestId,
    pub request: RequestMessage<Rq, Rs>,
}

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

#[derive(Debug)]
pub enum NetworkEvents {
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
    ConnectionEstablished {
        peer: PeerId,
        endpoint: ConnectedPoint,
        num_established: NonZeroU32,
    },
    ConnectionClosed {
        peer: PeerId,
        endpoint: ConnectedPoint,
        num_established: u32,
        cause: Option<io::Error>,
    },
    IncomingConnectionError {
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
        error: ConnectionErr,
    },
    NewListenAddr(Multiaddr),
    ExpiredListenAddr(Multiaddr),
    ListenerClosed {
        addresses: Vec<Multiaddr>,
        cause: Option<io::Error>,
    },
    ListenerError {
        error: io::Error,
    },
}

pub(crate) type SwarmEv<Rq, Rs, THandleErr> = SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>;

impl<Rq: RqRsMessage, Rs: RqRsMessage, THandleErr> TryFrom<SwarmEv<Rq, Rs, THandleErr>> for NetworkEvents {
    type Error = ();
    fn try_from(value: SwarmEv<Rq, Rs, THandleErr>) -> Result<Self, Self::Error> {
        match value {
            SwarmEvent::Behaviour(ev) => match ev {
                BehaviourEvent::Request(_) => Err(()),
                BehaviourEvent::OutboundFailure {
                    request_id,
                    peer,
                    failure,
                } => Ok(NetworkEvents::OutboundFailure {
                    request_id,
                    peer,
                    failure,
                }),
                BehaviourEvent::InboundFailure {
                    request_id,
                    peer,
                    failure,
                } => Ok(NetworkEvents::InboundFailure {
                    request_id,
                    peer,
                    failure,
                }),
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
            } => Ok(NetworkEvents::ConnectionEstablished {
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
                Ok(NetworkEvents::ConnectionClosed {
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
            } => Ok(NetworkEvents::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error: error.into(),
            }),
            SwarmEvent::ExpiredListenAddr(addr) => Ok(NetworkEvents::ExpiredListenAddr(addr)),
            SwarmEvent::ListenerClosed { addresses, reason } => {
                let cause = match reason {
                    Ok(()) => None,
                    Err(e) => Some(e),
                };
                Ok(NetworkEvents::ListenerClosed { addresses, cause })
            }
            SwarmEvent::ListenerError { error } => Ok(NetworkEvents::ListenerError { error }),
            SwarmEvent::NewListenAddr(addr) => Ok(NetworkEvents::NewListenAddr(addr)),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundFailure {
    Timeout,
    DialFailure,
    ConnectionClosed,
    RecvResponseOmission,
    UnsupportedProtocols,
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
    Timeout,
    NotPermitted,
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

#[derive(Debug)]
pub enum ConnectionErr {
    Io(io::Error),
    InvalidPeerId,
    MultiaddrNotSupported(Multiaddr),
    ConnectionLimit { limit: u32, current: u32 },
}

impl fmt::Display for ConnectionErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectionErr::Io(err) => write!(f, "Pending connection: I/O error: {}", err),
            ConnectionErr::InvalidPeerId => write!(f, "Pending connection: Invalid peer ID."),
            ConnectionErr::ConnectionLimit { current, limit } => {
                write!(f, "Connection error: Connection limit: {}/{}.", current, limit)
            }
            ConnectionErr::MultiaddrNotSupported(a) => write!(
                f,
                "Pending connection: Transport error: Multiaddr is not supported: {}",
                a
            ),
        }
    }
}

impl From<PendingConnectionError<io::Error>> for ConnectionErr {
    fn from(value: PendingConnectionError<io::Error>) -> Self {
        match value {
            PendingConnectionError::Transport(TransportError::Other(e)) | PendingConnectionError::IO(e) => {
                ConnectionErr::Io(e)
            }
            PendingConnectionError::InvalidPeerId => ConnectionErr::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                ConnectionErr::ConnectionLimit { limit, current }
            }
            PendingConnectionError::Transport(TransportError::MultiaddrNotSupported(a)) => {
                ConnectionErr::MultiaddrNotSupported(a)
            }
        }
    }
}

impl std::error::Error for OutboundFailure {}
impl std::error::Error for InboundFailure {}
impl std::error::Error for ConnectionErr {}

#[derive(Debug)]
pub enum BehaviourEvent<Rq, Rs> {
    Request(ReceiveRequest<Rq, Rs>),
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
}

impl<Rq, Rs> Unpin for BehaviourEvent<Rq, Rs> {}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::{
    core::connection::{ConnectionLimit, PendingConnectionError},
    swarm::DialError,
    Multiaddr, TransportError,
};
use std::{fmt, io};

#[derive(Debug)]
pub enum DialErr {
    Banned,
    ConnectionLimit { limit: u32, current: u32 },
    InvalidAddress(Multiaddr),
    UnreachableAddr(Multiaddr),
    NoAddresses,
}

impl From<DialError> for DialErr {
    fn from(err: DialError) -> Self {
        match err {
            DialError::Banned => DialErr::Banned,
            DialError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                DialErr::ConnectionLimit { limit, current }
            }
            DialError::InvalidAddress(addr) => DialErr::InvalidAddress(addr),
            DialError::NoAddresses => DialErr::NoAddresses,
        }
    }
}

impl fmt::Display for DialErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialErr::ConnectionLimit { limit, current } => {
                write!(f, "Dial error: Connection limit: {}/{}.", current, limit)
            }
            DialErr::NoAddresses => write!(f, "Dial error: no addresses for peer."),
            DialErr::InvalidAddress(a) => write!(f, "Dial error: invalid address: {}", a),
            DialErr::UnreachableAddr(a) => write!(f, "Dial error: unreachable address: {}", a),
            DialErr::Banned => write!(f, "Dial error: peer is banned."),
        }
    }
}

impl std::error::Error for DialErr {}

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
            ConnectionErr::Io(err) => write!(f, "Connection error: I/O error: {}", err),
            ConnectionErr::InvalidPeerId => write!(f, "Connection error: Invalid peer ID."),
            ConnectionErr::ConnectionLimit { current, limit } => {
                write!(f, "Connection error: Connection limit: {}/{}.", current, limit)
            }
            ConnectionErr::MultiaddrNotSupported(a) => write!(
                f,
                "Connection error: Transport error: Multiaddr is not supported: {}",
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

impl std::error::Error for ConnectionErr {}

#[derive(Debug)]
pub enum TransportErr {
    MultiaddrNotSupported(Multiaddr),
    Io(io::Error),
}

impl fmt::Display for TransportErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TransportErr::MultiaddrNotSupported(a) => write!(f, "Transport error: Multiaddress not supported: {}", a),
            TransportErr::Io(err) => write!(f, "Transport error: I/O error: {}", err),
        }
    }
}

impl From<TransportError<io::Error>> for TransportErr {
    fn from(err: TransportError<io::Error>) -> Self {
        match err {
            TransportError::MultiaddrNotSupported(addr) => TransportErr::MultiaddrNotSupported(addr),
            TransportError::Other(err) => TransportErr::Io(err),
        }
    }
}

impl std::error::Error for TransportErr {}

#[derive(Debug)]
pub enum ListenRelayErr {
    DialRelay(DialErr),
    Transport(TransportErr),
}

impl From<DialError> for ListenRelayErr {
    fn from(err: DialError) -> Self {
        ListenRelayErr::DialRelay(err.into())
    }
}

impl From<DialErr> for ListenRelayErr {
    fn from(err: DialErr) -> Self {
        ListenRelayErr::DialRelay(err)
    }
}

impl From<TransportError<io::Error>> for ListenRelayErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenRelayErr::Transport(err.into())
    }
}

impl fmt::Display for ListenRelayErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ListenRelayErr::DialRelay(e) => write!(f, "Listen on Relay error: Dial Relay Error: {}", e),
            ListenRelayErr::Transport(e) => write!(f, "Listen on Relay error: Transport Error: {}", e),
        }
    }
}

impl std::error::Error for ListenRelayErr {}

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

use libp2p::{
    core::connection::{ConnectionLimit, PendingConnectionError},
    swarm::DialError,
    Multiaddr, TransportError,
};
use std::{convert::TryFrom, fmt, io};

/// Error on dialing a peer and establishing a connection.
#[derive(Debug)]
pub enum DialErr {
    /// The peer is currently banned.
    Banned,
    /// The configured limit for simultaneous outgoing connections
    /// has been reached.
    ConnectionLimit { limit: u32, current: u32 },
    /// The peer being dialed is the local peer and thus the dial was aborted.
    LocalPeerId,
    /// No direct or relayed addresses for the peer are known.
    NoAddresses,
    /// Pending connection attempt has been aborted.
    Aborted,
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    InvalidPeerId,
    /// An I/O error occurred on the connection.
    ConnectionIo(io::Error),
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    Transport(Vec<(Multiaddr, TransportError<io::Error>)>),
    /// The communication system was shut down before the dialing attempt resolved.
    Shutdown,
}

impl TryFrom<DialError> for DialErr {
    type Error = ();
    fn try_from(err: DialError) -> Result<Self, Self::Error> {
        let e = match err {
            DialError::Banned => DialErr::Banned,
            DialError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                DialErr::ConnectionLimit { limit, current }
            }
            DialError::LocalPeerId => DialErr::LocalPeerId,
            DialError::NoAddresses => DialErr::NoAddresses,
            DialError::DialPeerConditionFalse(_) => return Err(()),
            DialError::Aborted => DialErr::Aborted,
            DialError::InvalidPeerId => DialErr::InvalidPeerId,
            DialError::ConnectionIo(e) => DialErr::ConnectionIo(e),
            DialError::Transport(addrs) => DialErr::Transport(addrs),
        };
        Ok(e)
    }
}

impl fmt::Display for DialErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialErr::ConnectionLimit { limit, current } => {
                write!(f, "Dial error: Connection limit: {}/{}.", current, limit)
            }
            DialErr::NoAddresses => write!(f, "Dial error: no addresses for peer."),
            DialErr::LocalPeerId => write!(f, "Dial error: tried to dial local peer id."),
            DialErr::Banned => write!(f, "Dial error: peer is banned."),
            DialErr::Aborted => write!(f, "Dial error: Pending connection attempt has been aborted."),
            DialErr::InvalidPeerId => write!(f, "Dial error: Invalid peer ID."),
            DialErr::ConnectionIo(e) => write!(f, "Dial error: An I/O error occurred on the connection: {:?}.", e),
            DialErr::Transport(e) => write!(
                f,
                "An error occurred while negotiating the transport protocol(s) on a connection: {:?}.",
                e
            ),
            DialErr::Shutdown => write!(f, "Dial error: the network task was shut down."),
        }
    }
}

impl std::error::Error for DialErr {}

/// Error on establishing a connection.
#[derive(Debug)]
pub enum ConnectionErr {
    /// An I/O error occurred on the connection.
    Io(io::Error),
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    InvalidPeerId,
    /// An error occurred while negotiating the transport protocol(s).
    Transport(TransportErr),
    /// The connection was dropped because the connection limit
    /// for a peer has been reached.
    ConnectionLimit { limit: u32, current: u32 },
    /// Pending connection attempt has been aborted.
    Aborted,
}

impl fmt::Display for ConnectionErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectionErr::Io(err) => write!(f, "Connection error: I/O error: {}", err),
            ConnectionErr::InvalidPeerId => write!(f, "Connection error: Invalid peer ID."),
            ConnectionErr::ConnectionLimit { current, limit } => {
                write!(f, "Connection error: Connection limit: {}/{}.", current, limit)
            }
            ConnectionErr::Transport(e) => write!(f, "Connection error: Transport error: {}", e),
            ConnectionErr::Aborted => write!(f, "Pending connection attempt has been aborted"),
        }
    }
}

impl From<PendingConnectionError<TransportError<io::Error>>> for ConnectionErr {
    fn from(value: PendingConnectionError<TransportError<io::Error>>) -> Self {
        match value {
            PendingConnectionError::Transport(TransportError::Other(e)) | PendingConnectionError::IO(e) => {
                ConnectionErr::Io(e)
            }
            PendingConnectionError::InvalidPeerId => ConnectionErr::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(ConnectionLimit { limit, current }) => {
                ConnectionErr::ConnectionLimit { limit, current }
            }
            PendingConnectionError::Transport(err) => ConnectionErr::Transport(err.into()),
            PendingConnectionError::Aborted => ConnectionErr::Aborted,
        }
    }
}

impl std::error::Error for ConnectionErr {}

/// Error on the [Transport][libp2p::Transport].
#[derive(Debug)]
pub enum TransportErr {
    /// The address is not supported.
    MultiaddrNotSupported(Multiaddr),
    /// An I/O Error occurred.
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

/// Error on listening on an address.
#[derive(Debug)]
pub enum ListenErr {
    /// Listening on the address failed on the transport layer.
    Transport(TransportErr),
    /// The communication system was shut down before the listening attempt resolved.
    Shutdown,
}

impl From<TransportError<io::Error>> for ListenErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenErr::Transport(err.into())
    }
}

impl fmt::Display for ListenErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ListenErr::Transport(e) => write!(f, "Listen error: Transport Error: {}", e),
            ListenErr::Shutdown => write!(f, "Listen error: the network task was shut down."),
        }
    }
}

impl std::error::Error for ListenErr {}

/// Error on listening on a relayed address.
#[derive(Debug)]
pub enum ListenRelayErr {
    /// The relay protocol is not supported.
    ProtocolNotSupported,
    /// Establishing a connection to the relay failed.
    DialRelay(DialErr),
    /// Listening on the address failed on the transport layer.
    Transport(TransportErr),
    /// The communication system was shut down before the listening attempt resolved.
    Shutdown,
}

impl TryFrom<DialError> for ListenRelayErr {
    type Error = <DialErr as TryFrom<DialError>>::Error;
    fn try_from(err: DialError) -> Result<Self, Self::Error> {
        DialErr::try_from(err).map(ListenRelayErr::DialRelay)
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
            ListenRelayErr::ProtocolNotSupported => write!(f, "Listen on Relay error: Relay Protocol not supported"),
            ListenRelayErr::DialRelay(e) => write!(f, "Listen on Relay error: Dial Relay Error: {}", e),
            ListenRelayErr::Transport(e) => write!(f, "Listen on Relay error: Listening Error: {}", e),
            ListenRelayErr::Shutdown => write!(f, "Listen on Relay error: the network task was shut down."),
        }
    }
}

impl std::error::Error for ListenRelayErr {}

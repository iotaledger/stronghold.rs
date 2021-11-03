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
use std::{convert::TryFrom, io};
use thiserror::Error;

/// Error on dialing a peer and establishing a connection.
#[derive(Error, Debug)]
pub enum DialErr {
    /// The peer is currently banned.
    #[error("Peer is banned.")]
    Banned,
    /// The configured limit for simultaneous outgoing connections
    /// has been reached.
    #[error("Connection limit: `{limit}`/`{current}`.")]
    ConnectionLimit { limit: u32, current: u32 },
    /// The peer being dialed is the local peer and thus the dial was aborted.
    #[error("Tried to dial local peer id.")]
    LocalPeerId,
    /// No direct or relayed addresses for the peer are known.
    #[error("No addresses known for peer.")]
    NoAddresses,
    /// Pending connection attempt has been aborted.
    #[error(" Pending connection attempt has been aborted.")]
    Aborted,
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    #[error("Invalid peer ID.")]
    InvalidPeerId,
    /// An I/O error occurred on the connection.
    #[error("An I/O error occurred on the connection: {0}.")]
    ConnectionIo(io::Error),
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    #[error("An error occurred while negotiating the transport protocol(s) on a connection: `{0:?}`.")]
    Transport(Vec<(Multiaddr, TransportError<io::Error>)>),
    /// The communication system was shut down before the dialing attempt resolved.
    #[error("The network task was shut down.")]
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

/// Error on establishing a connection.
#[derive(Error, Debug)]
pub enum ConnectionErr {
    /// An I/O error occurred on the connection.
    #[error("I/O error: {0}")]
    Io(io::Error),
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    #[error("Invalid peer ID.")]
    InvalidPeerId,
    /// An error occurred while negotiating the transport protocol(s).
    #[error("Transport error: {0}")]
    Transport(TransportErr),
    /// The connection was dropped because the connection limit
    /// for a peer has been reached.
    #[error("Connection limit: `{limit}`/`{current}`.")]
    ConnectionLimit { limit: u32, current: u32 },
    /// Pending connection attempt has been aborted.
    #[error("Pending connection attempt has been aborted.")]
    Aborted,
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

/// Error on the [Transport][libp2p::Transport].
#[derive(Error, Debug)]
pub enum TransportErr {
    /// The address is not supported.
    #[error("Multiaddress not supported: {0}")]
    MultiaddrNotSupported(Multiaddr),
    /// An I/O Error occurred.
    #[error("I/O error: {0}")]
    Io(io::Error),
}

impl From<TransportError<io::Error>> for TransportErr {
    fn from(err: TransportError<io::Error>) -> Self {
        match err {
            TransportError::MultiaddrNotSupported(addr) => TransportErr::MultiaddrNotSupported(addr),
            TransportError::Other(err) => TransportErr::Io(err),
        }
    }
}

/// Error on listening on an address.
#[derive(Error, Debug)]
pub enum ListenErr {
    /// Listening on the address failed on the transport layer.
    #[error("Transport error: {0}")]
    Transport(TransportErr),
    /// The communication system was shut down before the listening attempt resolved.
    #[error("The network task was shut down.")]
    Shutdown,
}

impl From<TransportError<io::Error>> for ListenErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenErr::Transport(err.into())
    }
}

/// Error on listening on a relayed address.
#[derive(Error, Debug)]
pub enum ListenRelayErr {
    /// The relay protocol is not supported.
    #[error("Relay Protocol not enabled.")]
    ProtocolNotSupported,
    /// Establishing a connection to the relay failed.
    #[error("Dial Relay Error: {0}")]
    DialRelay(#[from] DialErr),
    /// Error on listening on an address.
    #[error("Listening Error: {0}")]
    Listen(ListenErr),
}

impl TryFrom<DialError> for ListenRelayErr {
    type Error = <DialErr as TryFrom<DialError>>::Error;
    fn try_from(err: DialError) -> Result<Self, Self::Error> {
        DialErr::try_from(err).map(ListenRelayErr::DialRelay)
    }
}

impl From<TransportError<io::Error>> for ListenRelayErr {
    fn from(err: TransportError<io::Error>) -> Self {
        ListenRelayErr::Listen(err.into())
    }
}

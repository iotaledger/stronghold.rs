// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::message::{P2PIdentifyEvent, P2PInboundFailure, P2PMdnsEvent, P2POutboundFailure};
use libp2p::{
    core::{connection::PendingConnectionError, Multiaddr, PeerId},
    swarm::DialError,
};

pub use libp2p::core::connection::ConnectionLimit;

/// Errors that can occur in the context of a pending `Connection`.
#[derive(Debug, Clone)]
pub enum ConnectPeerError {
    /// The peer is currently banned.
    Banned,
    /// No addresses for the peer to dial
    NoAddresses,
    /// An error occurred while negotiating the transport protocol(s).
    Transport,
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    InvalidPeerId,
    /// The connection was dropped because the connection limit
    /// for a peer has been reached.
    ConnectionLimit(ConnectionLimit),
    /// An I/O error occurred on the connection.
    IO,
}

impl<TTransErr> From<PendingConnectionError<TTransErr>> for ConnectPeerError {
    fn from(error: PendingConnectionError<TTransErr>) -> Self {
        match error {
            PendingConnectionError::Transport(_) => ConnectPeerError::Transport,
            PendingConnectionError::InvalidPeerId => ConnectPeerError::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(limit) => ConnectPeerError::ConnectionLimit(limit),
            PendingConnectionError::IO(_) => ConnectPeerError::IO,
        }
    }
}

impl From<DialError> for ConnectPeerError {
    fn from(error: DialError) -> Self {
        match error {
            DialError::Banned => ConnectPeerError::Banned,
            DialError::ConnectionLimit(limit) => ConnectPeerError::ConnectionLimit(limit),
            DialError::NoAddresses => ConnectPeerError::NoAddresses,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommunicationRequest<T> {
    RequestMsg {
        peer_id: PeerId,
        client_str: String,
        request: T,
    },
    ConnectPeerId(PeerId),
    ConnectPeerAddr(Multiaddr),
    CheckConnection(PeerId),
    GetSwarmInfo,
    BanPeer(PeerId),
    UnbanPeer(PeerId),
    StartListening(Option<Multiaddr>),
    RemoveListener(Multiaddr),
}

#[derive(Debug, Clone)]
pub enum RequestMessageError {
    NoClient(String),
    Outbound(P2POutboundFailure),
    Inbound(P2PInboundFailure),
}

#[derive(Debug, Clone)]
pub enum CommunicationResults<U> {
    RequestMsgResult(Result<U, RequestMessageError>),
    ConnectPeerResult(Result<PeerId, ConnectPeerError>),
    CheckConnectionResult(bool),
    SwarmInfo { peer_id: PeerId, listeners: Vec<Multiaddr> },
    BannedPeer { peer_id: PeerId, addr: Multiaddr },
    UnbannedPeer(PeerId),
    StartListeningResult(Result<Multiaddr, ()>),
    RemoveListenerResult(Result<(), ()>),
}

#[derive(Debug, Clone)]
pub enum SwarmEvent {
    Mdns(P2PMdnsEvent),
    Identify(Box<P2PIdentifyEvent>),
    PeerConnected(PeerId),
    IncomingConnection(Multiaddr),
    ConnectionEstablished {
        peer_id: PeerId,
        addr: Multiaddr,
    },
    IncomingConnectionError {
        peer_addr: Multiaddr,
        local_addr: Multiaddr,
        error: ConnectPeerError,
    },
    ListenerClosed {
        addresses: Vec<Multiaddr>,
        reason: Result<(), String>,
    },
}

#[derive(Debug, Clone)]
pub enum CommunicationEvent<T, U> {
    Request(CommunicationRequest<T>),
    Results(CommunicationResults<U>),
    Swarm(Box<SwarmEvent>),
    Shutdown,
}

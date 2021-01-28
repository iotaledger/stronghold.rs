// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::message::{P2PIdentifyEvent, P2PInboundFailure, P2PMdnsEvent, P2POutboundFailure};
use libp2p::{
    core::{
        connection::{ConnectionError, PendingConnectionError},
        ConnectedPoint, Multiaddr, PeerId,
    },
    swarm::DialError,
};
use riker::{actors::ActorRef, Message};

use core::num::NonZeroU32;
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
    /// The connection handler produced an error.
    Handler,
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

impl<THandlerErr> From<ConnectionError<THandlerErr>> for ConnectPeerError {
    fn from(error: ConnectionError<THandlerErr>) -> Self {
        match error {
            ConnectionError::Handler(_) => ConnectPeerError::Handler,
            ConnectionError::IO(_) => ConnectPeerError::IO,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerTarget {
    Id(PeerId),
    Addr(Multiaddr),
}

#[derive(Debug, Clone)]
pub enum CommunicationRequest<Req, T: Message> {
    RequestMsg { peer_id: PeerId, request: Req },
    SetClientRef(ActorRef<T>),
    ConnectPeer { addr: Multiaddr, peer_id: PeerId },
    CheckConnection(PeerId),
    GetSwarmInfo,
    BanPeer(PeerId),
    UnbanPeer(PeerId),
    StartListening(Option<Multiaddr>),
    RemoveListener,
}

#[derive(Debug, Clone)]
pub enum RequestMessageError {
    Outbound(P2POutboundFailure),
    Inbound(P2PInboundFailure),
}

#[derive(Debug, Clone)]
pub enum CommunicationResults<Res, T: Message> {
    RequestMsgResult(Result<Res, RequestMessageError>),
    SetClientRefResult(ActorRef<T>),
    ConnectPeerResult(Result<PeerId, ConnectPeerError>),
    CheckConnectionResult(bool),
    SwarmInfo { peer_id: PeerId, listeners: Vec<Multiaddr> },
    BannedPeer(PeerId),
    UnbannedPeer(PeerId),
    StartListeningResult(Result<Multiaddr, ()>),
    RemoveListenerResult(Result<(), ()>),
}

#[derive(Debug, Clone)]
pub enum CommunicationSwarmEvent {
    Mdns(P2PMdnsEvent),
    Identify(Box<P2PIdentifyEvent>),
    IncomingConnectionEstablished {
        peer_id: PeerId,
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
        num_established: NonZeroU32,
    },
    ConnectionClosed {
        peer_id: PeerId,
        endpoint: ConnectedPoint,
        num_established: NonZeroU32,
        cause: Option<ConnectPeerError>,
    },
    IncomingConnection {
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
    },
    IncomingConnectionError {
        peer_addr: Multiaddr,
        local_addr: Multiaddr,
        error: ConnectPeerError,
    },
    ExpiredListenAddr(Multiaddr),
    ListenerClosed {
        addresses: Vec<Multiaddr>,
        reason: Result<(), String>,
    },
    ListenerError(String),
}

#[derive(Debug, Clone)]
pub enum CommunicationEvent<Req, Res, T: Message> {
    Request(CommunicationRequest<Req, T>),
    Results(CommunicationResults<Res, T>),
    Swarm(CommunicationSwarmEvent),
    Shutdown,
}

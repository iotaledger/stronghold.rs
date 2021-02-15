// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{P2PInboundFailure, P2POutboundFailure};
use libp2p::{
    core::{
        connection::{ConnectionError, ConnectionLimit, PendingConnectionError},
        ConnectedPoint, Multiaddr, PeerId,
    },
    swarm::DialError,
};
use riker::{actors::ActorRef, Message};

use core::num::NonZeroU32;

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
    /// Timout on connection attempt
    Timeout,
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

/// Relay peer for outgoing request.
#[derive(Debug, Clone)]
pub enum RelayConfig {
    /// No relay should be used, peers can only be dialed directly.
    NoRelay,
    /// Always send requests to remote peers via the relay.
    RelayAlways(PeerId),
    /// Use relay peer if sending the request directly failed,
    RelayBackup(PeerId),
}

/// Requests for the [`CommuncationActor`]
#[derive(Debug, Clone)]
pub enum CommunicationRequest<Req, T: Message> {
    /// Send a request to a remote peer.
    /// This requires that a connection to the targeted peer has been established and is active.
    RequestMsg { peer_id: PeerId, request: Req },
    /// Set the actor reference that incoming request are forwarded to.
    SetClientRef(ActorRef<T>),
    /// Connect to a remote peer.
    /// If the peer id is know it will attempt to use a know address of it, otherwise the `addr` will be dialed.
    ConnectPeer { addr: Multiaddr, peer_id: PeerId },
    /// Check if a connection to that peer is currently active.
    CheckConnection(PeerId),
    /// Obtain information about the swarm.
    GetSwarmInfo,
    /// Ban a peer, which prevent any connection to that peer.
    BanPeer(PeerId),
    /// Unban a peer to allow future communication.
    UnbanPeer(PeerId),
    /// Start listening to a port on the swarm. If no `Multiaddr` is provided, the address will be OS assigned.ActorRef
    StartListening(Option<Multiaddr>),
    /// Stop listening to the swarm. Without a listener, the local peer can not be dialed from remote.
    RemoveListener,
    /// Configured if a relay peer should be used for requests
    SetRelay(RelayConfig),
    /// Shutdown communication actor.
    Shutdown,
}

/// The firewall that rejected or dropped the request
#[derive(Debug, Clone)]
pub enum FirewallBlocked {
    Local,
    Remote,
}

#[derive(Debug, Clone)]
pub enum RequestMessageError {
    /// Possible failures occurring in the context of sending an outbound request and receiving the response.
    Outbound(P2POutboundFailure),
    /// Possible failures occurring in the context of receiving an inbound request and sending a response.
    Inbound(P2PInboundFailure),
    /// The request was rejected or dropped by the local or remote firewall.
    Rejected(FirewallBlocked),
}

/// Returned results from the [`CommuncationActor`]
#[derive(Debug, Clone)]
pub enum CommunicationResults<Res> {
    /// Response or Error for an [`RequestMsg`] to a remote peer
    RequestMsgResult(Result<Res, RequestMessageError>),
    /// New client actor reference was set.
    SetClientRefResult,
    /// Result of trying to connect a peer.
    ConnectPeerResult(Result<PeerId, ConnectPeerError>),
    /// Check if the connection exists
    CheckConnectionResult(bool),
    /// Information about the local swarm.
    SwarmInfo {
        /// The local peer id.
        peer_id: PeerId,
        /// The listening addresses of the local system.
        /// Not all of theses addresses can be reached from outside of the network since they might be localhost or
        /// private IPs.
        listeners: Vec<Multiaddr>,
    },
    BannedPeer(PeerId),
    UnbannedPeer(PeerId),
    /// Result of starting a new listener on the swarm.
    /// If it was successfull, one of the listening addresses is returned, which will show the listening port.
    StartListeningResult(Result<Multiaddr, ()>),
    /// Stopped listening to the swarm for incoming connections.
    RemoveListenerResult(Result<(), ()>),
    /// Success setting relay
    SetRelay,
}

/// Events that are received from the swarm without being initiated by the local system.
#[derive(Debug, Clone)]
pub enum CommunicationSwarmEvent {
    /// An incoming connection was successful.
    IncomingConnectionEstablished {
        peer_id: PeerId,
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
        num_established: NonZeroU32,
    },
    /// Connection was closed.
    ConnectionClosed {
        peer_id: PeerId,
        endpoint: ConnectedPoint,
        num_established: NonZeroU32,
        cause: Option<ConnectPeerError>,
    },
    /// Incoming connection attempt.
    IncomingConnection {
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
    },
    /// An incoming connection was not successful.
    IncomingConnectionError {
        peer_addr: Multiaddr,
        local_addr: Multiaddr,
        error: ConnectPeerError,
    },
    /// A listening address of the local peer has expired.
    ExpiredListenAddr(Multiaddr),
    /// The local listener closed.
    ListenerClosed {
        addresses: Vec<Multiaddr>,
        reason: Result<(), String>,
    },
    /// The local listener had an error.
    ListenerError(String),
}

/// The direction of a [`CommunicationRequest::RequestMsg`] that firewall receives.
#[derive(Debug, Clone)]
pub enum RequestDirection {
    In,
    Out,
}

/// Request to the firewall to obtain approval for a request from/ to a remote peer.
/// If no [`FirewallResponse::Accept`] is returned, the request will be rejected.
#[derive(Debug, Clone)]
pub struct FirewallRequest<Req> {
    request: Req,
    remote: PeerId,
    direction: RequestDirection,
}

impl<Req> FirewallRequest<Req> {
    pub fn new(request: Req, remote: PeerId, direction: RequestDirection) -> Self {
        FirewallRequest {
            request,
            remote,
            direction,
        }
    }
}

/// The expected response that should be send back from the firewall actor for a [`FirewallRequest`].
#[derive(Debug, Clone)]
pub enum FirewallResponse {
    Accept,
    Reject,
    Drop,
}

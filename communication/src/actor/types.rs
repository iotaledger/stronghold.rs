// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{P2PInboundFailure, P2POutboundFailure};
use libp2p::{
    core::{
        connection::{ConnectedPoint, ConnectionError, ConnectionLimit, PendingConnectionError},
        Multiaddr, PeerId,
    },
    swarm::DialError,
};
use riker::{actors::ActorRef, Message};

use crate::actor::firewall::FirewallRule;
use std::time::Instant;

/// Relay peer for outgoing request.
#[derive(Debug, Clone)]
pub enum RelayConfig {
    /// No relay should be used, peers can only be dialed directly.
    NoRelay,
    /// Always send requests to remote peers via the relay.
    RelayAlways { peer_id: PeerId, addr: Multiaddr },
    /// Use relay peer if sending the request directly failed,
    RelayBackup { peer_id: PeerId, addr: Multiaddr },
}

/// Determines if the local system should actively keep the connection alive
#[derive(Debug, Clone)]
pub enum KeepAlive {
    /// No keep-alive.
    None,
    /// Keep alive for a limited duration.
    Limited {
        /// End timestamp after whom the connection will not actively be kept alive anymore.
        /// This does not automatically mean that the connection is closed, since request-response message might keep
        /// it alive.
        ///
        /// If the connection should be completely stopped, the CommunicationRequest::CloseConnection should be send to
        /// the [`CommunicationActor`].
        end: Instant,
    },
    /// Keep alive until one of the peers close the connection.
    Unlimited,
}

/// Requests for the [`CommunicationActor`].
#[derive(Debug, Clone)]
pub enum CommunicationRequest<Req, ClientMsg: Message> {
    /// Send a request to a remote peer.
    /// This requires that a connection to the targeted peer has been established and is active.
    RequestMsg { peer_id: PeerId, request: Req },
    /// Set the actor reference that incoming request are forwarded to.
    SetClientRef(ActorRef<ClientMsg>),
    /// Connect to a remote peer.
    /// If the peer id is know it will attempt to use a know address of it, otherwise the `addr` will be dialed.
    EstablishConnection {
        addr: Multiaddr,
        peer_id: PeerId,
        keep_alive: KeepAlive,
    },
    /// Close the connection to a remote peer so that no more requests from that peer will be allowed.
    /// This does not directly close the underlying transport connection, which will close on timeout instead.
    CloseConnection(PeerId),
    /// Check if a connection to that peer is currently active.
    CheckConnection(PeerId),
    /// Obtain information about the swarm.
    GetSwarmInfo,
    /// Ban a peer, which prevents any connection to that peer.
    BanPeer(PeerId),
    /// Unban a peer to allow future communication.
    UnbanPeer(PeerId),
    /// Start listening to a port on the swarm. If no `Multiaddr` is provided, the address will be OS assigned.
    StartListening(Option<Multiaddr>),
    /// Stop listening to the swarm. Without a listener, the local peer can not be dialed from remote.
    RemoveListener,
    /// Configured if a relay peer should be used for requests
    SetRelay(RelayConfig),
    /// Add or remove a rule of the firewall.
    /// If a rule for a peer & direction combination already exists, it is overwritten.
    ConfigureFirewall(FirewallRule),
    /// Shutdown communication actor.
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum RequestMessageError {
    /// Possible failures occurring in the context of sending an outbound request and receiving the response.
    Outbound(P2POutboundFailure),
    /// Possible failures occurring in the context of receiving an inbound request and sending a response.
    Inbound(P2PInboundFailure),
    /// The request was rejected by the local firewall.
    LocalFirewallRejected,
}

/// Information about the connection with a remote peer as maintained in the ConnectionManager.
#[derive(Clone, Debug)]
pub struct EstablishedConnection {
    start: Instant,
    keep_alive: KeepAlive,
    connected_point: ConnectedPoint,
}

impl EstablishedConnection {
    pub fn new(keep_alive: KeepAlive, connected_point: ConnectedPoint) -> Self {
        EstablishedConnection {
            start: Instant::now(),
            keep_alive,
            connected_point,
        }
    }
    pub(super) fn is_keep_alive(&self) -> bool {
        match self.keep_alive {
            KeepAlive::Unlimited => true,
            KeepAlive::Limited { end } => Instant::now() <= end,
            _ => false,
        }
    }

    pub(super) fn set_keep_alive(&mut self, keep_alive: KeepAlive) {
        self.keep_alive = keep_alive;
    }
}

/// Returned results from the [`CommunicationActor`]
#[derive(Debug, Clone)]
pub enum CommunicationResults<Res> {
    /// Response or Error for an [`RequestMsg`] to a remote peer
    RequestMsgResult(Result<Res, RequestMessageError>),
    /// New client actor reference was set.
    SetClientRefAck,
    /// Result of trying to connect a peer.
    EstablishConnectionResult(Result<PeerId, ConnectPeerError>),
    /// Closed connection to peer.
    CloseConnectionAck,
    /// Check if the connection exists.
    CheckConnectionResult {
        peer_id: PeerId,
        is_connected: bool,
    },
    /// Information about the local swarm.
    SwarmInfo {
        /// The local peer id.
        peer_id: PeerId,
        /// The listening addresses of the local system.
        /// Not all of theses addresses can be reached from outside of the network since they might be localhost or
        /// private IPs.
        listeners: Vec<Multiaddr>,
        /// Established connections.
        connections: Vec<(PeerId, EstablishedConnection)>,
    },
    BannedPeerAck(PeerId),
    UnbannedPeerAck(PeerId),
    /// Result of starting a new listener on the swarm.
    /// If it was successful, one of the listening addresses is returned, which will show the listening port.
    StartListeningResult(Result<Multiaddr, ()>),
    /// Stopped listening to the swarm for incoming connections.
    RemoveListenerResult(Result<(), ()>),
    /// Setting relay result.
    /// Error if the relay peer could not be connected.
    SetRelayResult(Result<(), ConnectPeerError>),
    /// Successfully set firewall rule.
    ConfigureFirewallAck,
}

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
    /// The address given for dialing is invalid.
    InvalidAddress(Multiaddr),
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

impl<TTransErr> From<&PendingConnectionError<TTransErr>> for ConnectPeerError {
    fn from(error: &PendingConnectionError<TTransErr>) -> Self {
        match error {
            PendingConnectionError::Transport(_) => ConnectPeerError::Transport,
            PendingConnectionError::InvalidPeerId => ConnectPeerError::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(limit) => ConnectPeerError::ConnectionLimit(limit.clone()),
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
            DialError::InvalidAddress(addr) => ConnectPeerError::InvalidAddress(addr),
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

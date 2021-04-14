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

/// Direction for which a relay peer is used.
#[derive(Debug, Clone)]
pub enum RelayDirection {
    /// Use the relay if a peer can not be dialed directly.
    Dialing,
    /// Maintain a keep-alive connection to a relay peer that then can relay
    /// messages from remote peers to the local peer.
    Listening,
    /// Use the peer for Dialing and Listening.
    Both,
}

/// Requests for the [`CommunicationActor`].
#[derive(Debug, Clone)]
pub enum CommunicationRequest<Req, ClientMsg: Message> {
    /// Send a request to a remote peer.
    /// This requires that a connection to the targeted peer has been established and is active.
    RequestMsg { peer_id: PeerId, request: Req },
    /// Set the actor reference that incoming request are forwarded to.
    SetClientRef(ActorRef<ClientMsg>),
    /// Add dialing information for a peer.
    /// This will attempt to connect to the peer either by the address or by peer id if it is already known due to e.g.
    /// mDNS.
    /// If the targeted peer is not a relay, and can not be reached directly, it will be attempted to reach
    /// it through a relay, if there are any.
    AddPeer {
        peer_id: PeerId,
        addr: Option<Multiaddr>,
        is_relay: Option<RelayDirection>,
    },
    /// Get information about the swarm with local peer id, listening addresses and active connections.
    GetSwarmInfo,
    /// Ban a peer, which prevents any communication from / to that peer.
    BanPeer(PeerId),
    /// Unban a peer to allow future communication.
    UnbanPeer(PeerId),
    /// Start listening to a port on the swarm.
    /// If no `Multiaddr` is provided, the address will be OS assigned.
    StartListening(Option<Multiaddr>),
    /// Stop listening locally to the swarm. Without a listener, the local peer can not be directly dialed from remote.
    /// Relayed listening addresses will not be removed with this.
    RemoveListener,
    /// Configure to use a peer as relay for dialing, listening, or both.
    /// The peer has to be known, which means that it has to be added with `CommunicationRequest::AddPeer` before.
    /// Existing relay configuration for the same peer is overwritten with this.
    /// If the the direction includes listening on the relay.
    ConfigRelay { peer_id: PeerId, direction: RelayDirection },
    /// Stop using the peer as relay.
    RemoveRelay(PeerId),
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
    connected_point: ConnectedPoint,
    is_relay: Option<RelayDirection>,
}

impl EstablishedConnection {
    pub fn new(connected_point: ConnectedPoint, is_relay: Option<RelayDirection>) -> Self {
        EstablishedConnection {
            start: Instant::now(),
            connected_point,
            is_relay,
        }
    }
}

/// Returned results from the [`CommunicationActor`]
#[derive(Debug, Clone)]
pub enum CommunicationResults<Res> {
    /// Response or Error for an [`RequestMsg`] to a remote peer
    RequestMsgResult(Result<Res, RequestMessageError>),
    /// New client actor reference was set.
    SetClientRefAck,
    /// Result of trying to connect a peer after adding it.
    AddPeerResult(Result<PeerId, ConnectPeerError>),
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
    RemoveListenerAck,
    /// Result for configuring the Relay.
    /// Error if the relay could not be reached because no address is known or dialing the address failed.
    ConfigRelayResult(Result<PeerId, ConnectPeerError>),
    /// Successfully removed relay.
    RemoveRelayAck,
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
    Io,
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
            PendingConnectionError::IO(_) => ConnectPeerError::Io,
        }
    }
}

impl<TTransErr> From<&PendingConnectionError<TTransErr>> for ConnectPeerError {
    fn from(error: &PendingConnectionError<TTransErr>) -> Self {
        match error {
            PendingConnectionError::Transport(_) => ConnectPeerError::Transport,
            PendingConnectionError::InvalidPeerId => ConnectPeerError::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(limit) => ConnectPeerError::ConnectionLimit(limit.clone()),
            PendingConnectionError::IO(_) => ConnectPeerError::Io,
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
            ConnectionError::IO(_) => ConnectPeerError::Io,
        }
    }
}

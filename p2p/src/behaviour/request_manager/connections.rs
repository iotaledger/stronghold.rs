// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{RequestDirection, RequestId};
use libp2p::core::{connection::ConnectionId, PeerId};
use smallvec::SmallVec;
use std::collections::{hash_map::HashMap, HashSet};

// Sent requests that have not yet received a response.
#[derive(Debug)]
pub struct PendingResponses {
    // Outbound request sent to remote, waiting for an inbound response.
    pub outbound_requests: HashSet<RequestId>,
    // Inbound requests received from remote, waiting for an outbound response.
    pub inbound_requests: HashSet<RequestId>,
}

impl Default for PendingResponses {
    fn default() -> Self {
        PendingResponses {
            outbound_requests: Default::default(),
            inbound_requests: Default::default(),
        }
    }
}

// Active connections to a remote peer and pending responses on each connection.
#[derive(Debug)]
pub struct PeerConnectionManager {
    // Currently active connections for each peer.
    connections: HashMap<PeerId, SmallVec<[ConnectionId; 2]>>,
    // Pending responses for each active connection.
    pending_responses: HashMap<ConnectionId, PendingResponses>,
}

impl PeerConnectionManager {
    pub fn new() -> Self {
        PeerConnectionManager {
            connections: Default::default(),
            pending_responses: Default::default(),
        }
    }

    // Check if the local peer currently has at least one active connection to the remote.
    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.connections
            .get(peer)
            .map(|connections| !connections.is_empty())
            .unwrap_or(false)
    }

    // Get the ids of the active connections.
    pub fn get_connections(&self, peer: &PeerId) -> SmallVec<[ConnectionId; 2]> {
        self.connections.get(peer).cloned().unwrap_or_default()
    }

    // List of peers to which at least one connection is currently established.
    pub fn get_connected_peers(&self) -> Vec<PeerId> {
        self.connections.keys().copied().collect()
    }

    // Remove all connections of a peer, return the concatenated list of pending responses from the connections.
    pub fn remove_all_connections(&mut self, peer: &PeerId) -> Option<SmallVec<[ConnectionId; 2]>> {
        self.connections.remove(peer)
    }

    // Insert a newly established connection.
    pub fn add_connection(&mut self, peer: PeerId, connection: ConnectionId) {
        self.connections.entry(peer).or_default().push(connection);
    }

    // Remove a connection from the list, return the pending responses on that connection.
    pub fn remove_connection(&mut self, peer: PeerId, connection: &ConnectionId) -> Option<PendingResponses> {
        self.connections
            .entry(peer)
            .and_modify(|connections| connections.retain(|c| c != connection));
        if let Some(true) = self.connections.get(&peer).map(|conns| conns.is_empty()) {
            self.connections.remove(&peer);
        }
        self.pending_responses.remove(connection)
    }

    // New request that has been sent/ received, but with no response yet.
    // Assign the request to the provided connection or else to a random established one.
    // Return [`None`] if there are no connections.
    pub fn add_request(
        &mut self,
        peer: &PeerId,
        request_id: RequestId,
        connection: Option<ConnectionId>,
        direction: &RequestDirection,
    ) -> Option<ConnectionId> {
        let conns = self.connections.get(peer)?;
        let conn = match connection {
            Some(conn) => {
                // Check if the provided connection is active.
                conns.into_iter().find(|&c| c == &conn)?;
                conn
            }
            None => {
                // Assign request to a rather random connection.
                let index = (request_id.value() as usize) % conns.len();
                conns[index]
            }
        };
        let pending_responses = self
            .pending_responses
            .entry(conn)
            .or_insert_with(PendingResponses::default);
        match direction {
            RequestDirection::Inbound => pending_responses.inbound_requests.insert(request_id),
            RequestDirection::Outbound => pending_responses.outbound_requests.insert(request_id),
        };
        Some(conn)
    }

    // Remove a request from the list of pending responses.
    pub fn remove_request(&mut self, request_id: &RequestId, direction: &RequestDirection) {
        self.pending_responses.values_mut().for_each(|pending| {
            match direction {
                RequestDirection::Inbound => pending.inbound_requests.remove(request_id),
                RequestDirection::Outbound => pending.outbound_requests.remove(request_id),
            };
        });
    }
}

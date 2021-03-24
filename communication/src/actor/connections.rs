// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{EstablishedConnection, KeepAlive};
use libp2p::{core::ConnectedPoint, PeerId};
use std::collections::HashMap;

// Maintain the current connection state to remote peers.
// If a connection is closed in the ConnectionManager, no request from that peer will be forwarded anymore, but the
// connection within the swarn is still alive. A connection in the swarm can only actively be closed by banning the
// peer, otherwise it closes on timeout.
//
// If multiple connections to a peer exist, the ConnectionManager will keep the properties of the first connection.
pub(super) struct ConnectionManager {
    map: HashMap<PeerId, EstablishedConnection>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        ConnectionManager { map: HashMap::new() }
    }

    // Returns all the currently active connections
    pub fn current_connections(&self) -> Vec<(PeerId, EstablishedConnection)> {
        self.map.clone().into_iter().collect()
    }

    // Insert connection information for new peer, if that peer is not known yet.
    pub fn insert(&mut self, peer_id: PeerId, connected_point: ConnectedPoint, keep_alive: KeepAlive) {
        if self.map.get(&peer_id).is_none() {
            let new_connection = EstablishedConnection::new(keep_alive, connected_point);
            self.map.insert(peer_id, new_connection);
        }
    }

    pub fn is_keep_alive(&self, peer_id: &PeerId) -> bool {
        self.map
            .get(&peer_id)
            .map(|connection| connection.is_keep_alive())
            .unwrap_or(false)
    }

    pub fn set_keep_alive(&mut self, peer_id: &PeerId, keep_alive: KeepAlive) {
        if let Some(connection) = self.map.get_mut(peer_id) {
            connection.set_keep_alive(keep_alive)
        }
    }

    pub fn remove_connection(&mut self, peer_id: &PeerId) {
        self.map.remove(peer_id);
    }
}

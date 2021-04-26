// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::EstablishedConnection;
use crate::actor::RelayDirection;
use libp2p::{core::ConnectedPoint, PeerId};
use std::collections::HashMap;

// Maintain the current connection state to remote peers.
// If a connection is closed in the ConnectionManager, no request from that peer will be forwarded anymore, but the
// connection within the swarm is still alive. A connection in the swarm can only actively be closed by banning the
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
    pub fn insert(&mut self, peer_id: PeerId, connected_point: ConnectedPoint, is_relay: Option<RelayDirection>) {
        if self.map.get(&peer_id).is_none() {
            let new_connection = EstablishedConnection::new(connected_point, is_relay);
            self.map.insert(peer_id, new_connection);
        }
    }

    pub fn remove_connection(&mut self, peer_id: &PeerId) {
        self.map.remove(peer_id);
    }
}

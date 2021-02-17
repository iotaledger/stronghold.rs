// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::{core::ConnectedPoint, PeerId};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct EstablishedConnection {
    start: Instant,
    connected_point: ConnectedPoint,
    duration: Option<Duration>,
    keep_alive: bool,
}

pub(super) struct ConnectionManager {
    connections: HashMap<PeerId, EstablishedConnection>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        ConnectionManager {
            connections: HashMap::new(),
        }
    }

    pub fn insert_connection(
        &mut self,
        peer_id: PeerId,
        connected_point: ConnectedPoint,
        duration: Option<Duration>,
        keep_alive: bool,
    ) {
        let new_connection = EstablishedConnection {
            start: Instant::now(),
            connected_point,
            duration,
            keep_alive,
        };
        self.connections.insert(peer_id, new_connection);
    }

    pub fn is_permitted(&mut self, peer_id: &PeerId) -> bool {
        self.update();
        self.connections.get(&peer_id).is_some()
    }

    pub fn is_keep_alive(&mut self, peer_id: &PeerId) -> bool {
        self.update();
        if let Some(connection) = self.connections.get(&peer_id) {
            connection.keep_alive
        } else {
            false
        }
    }

    pub fn remove_connection(&mut self, peer_id: &PeerId) {
        self.connections.remove(peer_id);
    }

    fn update(&mut self) {
        self.connections = self
            .connections
            .iter()
            .filter_map(|(&peer_id, connection)| {
                let connection = connection.clone();
                if let Some(duration) = connection.duration {
                    if Instant::now().duration_since(connection.start) < duration {
                        return None;
                    }
                }
                Some((peer_id, connection))
            })
            .collect();
    }
}

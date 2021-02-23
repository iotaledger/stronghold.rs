// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::KeepAlive;
use libp2p::{core::ConnectedPoint, PeerId};
use std::{collections::HashMap, time::Instant};

#[derive(Clone)]
struct EstablishedConnection {
    start: Instant,
    keep_alive: KeepAlive,
    connected_point: ConnectedPoint,
}

pub(super) struct ConnectionManager {
    map: HashMap<PeerId, EstablishedConnection>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        ConnectionManager { map: HashMap::new() }
    }

    pub fn insert(&mut self, peer_id: PeerId, connected_point: ConnectedPoint, keep_alive: KeepAlive) {
        if self.map.get(&peer_id).is_none() {
            let new_connection = EstablishedConnection {
                start: Instant::now(),
                keep_alive,
                connected_point,
            };
            self.map.insert(peer_id, new_connection);
        }
    }

    pub fn is_active_connection(&self, peer_id: &PeerId) -> bool {
        self.map.get(peer_id).is_some()
    }

    pub fn is_keep_alive(&mut self, peer_id: &PeerId) -> bool {
        match self.map.get(&peer_id) {
            Some(EstablishedConnection {
                start: _,
                keep_alive: KeepAlive::Unlimited,
                connected_point: _,
            }) => true,
            Some(EstablishedConnection {
                start: _,
                keep_alive: KeepAlive::Limited(end),
                connected_point: _,
            }) => Instant::now() <= *end,
            _ => false,
        }
    }

    pub fn set_keep_alive(&mut self, peer_id: &PeerId, keep_alive: KeepAlive) {
        if let Some(connection) = self.map.get_mut(peer_id) {
            connection.keep_alive = keep_alive
        }
    }

    pub fn remove_connection(&mut self, peer_id: &PeerId) {
        self.map.remove(peer_id);
    }
}

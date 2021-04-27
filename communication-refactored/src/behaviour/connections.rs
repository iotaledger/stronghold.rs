// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::types::{Direction, RequestId};
use libp2p::core::{connection::ConnectionId, Multiaddr, PeerId};
use smallvec::SmallVec;
use std::collections::{hash_map::HashMap, HashSet};

#[derive(Clone, Debug)]
pub(super) struct Connection {
    id: ConnectionId,
    pending_outbound_responses: HashSet<RequestId>,
    pending_inbound_responses: HashSet<RequestId>,
}

impl Connection {
    pub fn new(id: ConnectionId) -> Self {
        Self {
            id,
            pending_outbound_responses: Default::default(),
            pending_inbound_responses: Default::default(),
        }
    }

    pub fn insert_request(&mut self, request_id: RequestId, direction: &Direction) -> bool {
        match direction {
            Direction::Inbound => self.pending_inbound_responses.insert(request_id),
            Direction::Outbound => self.pending_outbound_responses.insert(request_id),
        }
    }

    pub fn remove_request(&mut self, request_id: &RequestId, direction: &Direction) -> bool {
        match direction {
            Direction::Inbound => self.pending_inbound_responses.remove(request_id),
            Direction::Outbound => self.pending_outbound_responses.remove(request_id),
        }
    }

    pub fn pending_requests(&self, direction: &Direction) -> &HashSet<RequestId> {
        match direction {
            Direction::Inbound => &self.pending_inbound_responses,
            Direction::Outbound => &self.pending_outbound_responses,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct PeerConnectionManager {
    connections: HashMap<PeerId, SmallVec<[Connection; 2]>>,
    addresses: HashMap<PeerId, SmallVec<[Multiaddr; 6]>>,
}

impl PeerConnectionManager {
    pub fn new() -> Self {
        PeerConnectionManager {
            connections: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.connections
            .get(peer)
            .map(|connections| !connections.is_empty())
            .unwrap_or(false)
    }

    pub fn remove_all_connections(&mut self, peer: &PeerId) {
        self.connections.remove(peer);
    }

    pub fn add_connection(&mut self, peer: PeerId, conn_id: ConnectionId, address: Multiaddr) {
        self.connections.entry(peer).or_default().push(Connection::new(conn_id));
        self.add_address(&peer, address);
    }

    pub fn remove_connection(&mut self, peer: PeerId, conn_id: &ConnectionId) -> Option<Connection> {
        let mut is_empty = false;
        let mut connection = None;
        self.connections.entry(peer).and_modify(|conns| {
            conns.retain(|c| {
                let is_same = c.id.eq(conn_id);
                if is_same {
                    connection.replace(c.clone());
                }
                !is_same
            });
            is_empty = conns.is_empty();
        });
        if is_empty {
            self.connections.remove(&peer);
        }
        connection
    }

    pub fn new_request(&mut self, peer: &PeerId, request_id: RequestId, direction: &Direction) -> Option<ConnectionId> {
        self.connections.get_mut(peer).map(|conns| {
            let index = (request_id.value() as usize) % conns.len();
            let conn = &mut conns[index];
            conn.insert_request(request_id, direction);
            conn.id
        })
    }

    pub fn remove_request(
        &mut self,
        peer: &PeerId,
        conn_id: &ConnectionId,
        request_id: &RequestId,
        direction: &Direction,
    ) -> bool {
        self.connections
            .get_mut(peer)
            .and_then(|conns| {
                conns
                    .iter_mut()
                    .find_map(|conn| conn.id.eq(conn_id).then(|| conn.remove_request(request_id, direction)))
            })
            .unwrap_or(false)
    }

    pub fn get_peer_addrs(&self, peer: &PeerId) -> Option<&SmallVec<[Multiaddr; 6]>> {
        self.addresses.get(peer)
    }

    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) {
        let addrs = self.addresses.entry(*peer).or_default();
        if addrs.iter().find(|a| a == &&address).is_none() {
            addrs.push(address);
        }
    }

    pub fn remove_address(&mut self, peer: PeerId, address: &Multiaddr) {
        let mut is_empty = false;
        self.addresses.entry(peer).and_modify(|addrs| {
            addrs.retain(|a| a != address);
            is_empty = addrs.is_empty();
        });
        if is_empty {
            self.addresses.remove(&peer);
        }
    }
}

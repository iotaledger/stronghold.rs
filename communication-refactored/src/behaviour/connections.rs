// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::types::RequestId;
use libp2p::core::{connection::ConnectionId, Multiaddr, PeerId};
use smallvec::SmallVec;
use std::collections::{hash_map::HashMap, HashSet};

pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug)]
pub(super) struct Connection {
    pub id: ConnectionId,
    pub pending_outbound_requests: HashSet<RequestId>,
    pub pending_inbound_requests: HashSet<RequestId>,
}

#[derive(Debug)]
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
        self.connections.entry(peer).or_default().push(Connection {
            id: conn_id,
            pending_outbound_requests: Default::default(),
            pending_inbound_requests: Default::default(),
        });
        self.add_address(&peer, address);
    }

    pub fn remove_connection(&mut self, peer: PeerId, conn_id: &ConnectionId) -> Option<Connection> {
        self.connections.remove(&peer).and_then(|conns| {
            let (mut is_conn, other) = conns
                .into_iter()
                .partition::<SmallVec<[Connection; 2]>, _>(|c| c.id.eq(conn_id));
            if !other.is_empty() {
                self.connections.insert(peer, other);
            }
            is_conn.pop()
        })
    }

    pub fn new_request(&mut self, peer: &PeerId, request_id: RequestId, direction: Direction) -> Option<ConnectionId> {
        self.connections.get_mut(peer).map(|conns| {
            let index = (request_id.value() as usize) % conns.len();
            let conn = &mut conns[index];
            match direction {
                Direction::Inbound => conn.pending_inbound_requests.insert(request_id),
                Direction::Outbound => conn.pending_outbound_requests.insert(request_id),
            };
            conn.id
        })
    }

    pub fn remove_request(
        &mut self,
        peer: &PeerId,
        conn_id: &ConnectionId,
        request_id: &RequestId,
        direction: Direction,
    ) -> bool {
        self.connections
            .get_mut(peer)
            .and_then(|conns| conns.iter_mut().find(|c| &c.id == conn_id))
            .map(|conn| match direction {
                Direction::Inbound => conn.pending_inbound_requests.remove(request_id),
                Direction::Outbound => conn.pending_outbound_requests.remove(request_id),
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

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        if let Some((peer, other)) = self.addresses.remove_entry(&peer).and_then(|(peer, mut addrs)| {
            addrs.retain(|a| !a.eq(&address));
            let is_not_emtpy = !addrs.is_empty();
            is_not_emtpy.then(|| (peer, addrs))
        }) {
            self.addresses.insert(peer, other);
        }
    }
}

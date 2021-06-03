// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{super::RequestId, RequestDirection};
use libp2p::core::{connection::ConnectionId, PeerId};
use smallvec::SmallVec;
use std::collections::{hash_map::HashMap, HashSet};

#[derive(Debug)]
pub(super) struct PendingResponses {
    pub outbound_requests: HashSet<RequestId>,
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

#[derive(Debug)]
pub(super) struct PeerConnectionManager {
    connections: HashMap<PeerId, SmallVec<[ConnectionId; 2]>>,
    pending_responses: HashMap<ConnectionId, PendingResponses>,
}

impl PeerConnectionManager {
    pub fn new() -> Self {
        PeerConnectionManager {
            connections: Default::default(),
            pending_responses: Default::default(),
        }
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.connections
            .get(peer)
            .map(|connections| !connections.is_empty())
            .unwrap_or(false)
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.keys().copied().collect()
    }

    pub fn remove_all_connections(&mut self, peer: &PeerId) -> Option<PendingResponses> {
        let conns = self.connections.remove(peer)?;
        let collected_pending_res = conns.iter().fold(PendingResponses::default(), |mut acc, connection| {
            if let Some(pending_res) = self.pending_responses.remove(connection) {
                acc.outbound_requests.extend(pending_res.outbound_requests);
                acc.inbound_requests.extend(pending_res.inbound_requests);
            }
            acc
        });
        Some(collected_pending_res)
    }

    pub fn add_connection(&mut self, peer: PeerId, connection: ConnectionId) {
        self.connections.entry(peer).or_default().push(connection);
    }

    pub fn remove_connection(&mut self, peer: PeerId, connection: &ConnectionId) -> Option<PendingResponses> {
        self.connections
            .entry(peer)
            .and_modify(|connections| connections.retain(|c| c != connection));
        if let Some(true) = self.connections.get(&peer).map(|conns| conns.is_empty()) {
            self.connections.remove(&peer);
        }
        self.pending_responses.remove(connection)
    }

    pub fn on_new_request(
        &mut self,
        peer: &PeerId,
        request_id: RequestId,
        direction: &RequestDirection,
    ) -> Option<ConnectionId> {
        let conns = self.connections.get(peer)?;
        let index = (request_id.value() as usize) % conns.len();
        let connection = conns[index];
        let pending_responses = self
            .pending_responses
            .entry(connection)
            .or_insert_with(PendingResponses::default);
        match direction {
            RequestDirection::Inbound => pending_responses.inbound_requests.insert(request_id),
            RequestDirection::Outbound => pending_responses.outbound_requests.insert(request_id),
        };
        Some(connection)
    }

    pub fn remove_request(
        &mut self,
        connection: &ConnectionId,
        request_id: &RequestId,
        direction: &RequestDirection,
    ) -> bool {
        self.pending_responses
            .get_mut(connection)
            .map(|requests| match direction {
                RequestDirection::Inbound => requests.inbound_requests.remove(request_id),
                RequestDirection::Outbound => requests.outbound_requests.remove(request_id),
            })
            .unwrap_or(false)
    }
}

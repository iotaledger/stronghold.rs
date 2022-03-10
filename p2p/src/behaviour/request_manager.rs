// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{ProtocolSupport, EMPTY_QUEUE_SHRINK_THRESHOLD};
use crate::{
    firewall::{FirewallRules, FwRequest, Rule, RuleDirection},
    unwrap_or_return, InboundFailure, OutboundFailure, RequestDirection, RequestId,
};

use futures::channel::oneshot;
pub use libp2p::core::{connection::ConnectionId, ConnectedPoint};
use libp2p::PeerId;
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};
use wasm_timer::Instant;

// Actions for the behaviour to handle i.g. the behaviour emits the appropriate `NetworkBehaviourAction`.
pub enum BehaviourAction<Rq, Rs> {
    // Approved inbound request to forward to the user.
    InboundOk {
        request_id: RequestId,
        peer: PeerId,
        request: Rq,
        response_tx: oneshot::Sender<Rs>,
    },
    // Failures on inbound requests.
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    // Outbound request ready to be handled by the `NetBehaviour`.
    OutboundOk {
        request_id: RequestId,
        peer: PeerId,
        request: Rq,
        // The connection and handler that this request was assigned to.
        connection: ConnectionId,
    },
    // Failures on outbound requests.
    OutboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: OutboundFailure,
    },
    // Received response to a previously sent outbound request.
    OutboundReceivedRes {
        request_id: RequestId,
        peer: PeerId,
        response: Rs,
    },
    // Required dial attempt to connect a peer where at least one approved outbound request is pending.
    RequireDialAttempt(PeerId),
    // Configure if the handler should support inbound / outbound requests.
    SetProtocolSupport {
        peer: PeerId,
        // The target connection.
        // For each [`ConnectionId`], a separate handler is running.
        connection: ConnectionId,
        support: ProtocolSupport,
    },
}

// The status of a new request according to the firewall rules of the associated peer.
#[derive(Debug)]
pub enum ApprovalStatus {
    // Neither a peer specific, nor a default rule for the peer + direction exists.
    // A FirewallRequest::PeerSpecificRule has been send and the `NetBehaviour` currently awaits a response.
    MissingRule,
    // For the peer + direction, the Rule::Ask is set, which requires explicit approval.
    // The `NetBehaviour` sent a `FirewallRequest::RequestApproval` and currently awaits the approval.
    MissingApproval,
    // The request is approved by the current firewall rules.
    Approved,
    // The request is rejected by the current firewall rules.
    Rejected,
}

// Manager for pending requests that are awaiting a peer rule, individual approval, or a connection to the remote.
//
// Stores pending requests, manages rule, approval and connection changes, and queues required [`BehaviourActions`] for
// the `NetBehaviour` to handle.
#[derive(Default)]
pub struct RequestManager<Rq, Rs> {
    // Currently active connections for each peer.
    established_connections: HashMap<PeerId, EstablishedConnections>,

    // Cache of inbound requests that have not been approved yet.
    inbound_requests_cache: HashMap<RequestId, (PeerId, Rq, oneshot::Sender<Rs>)>,
    // Cache of outbound requests that have not been approved, or where the target peer is not connected yet.
    outbound_requests_cache: HashMap<RequestId, (PeerId, Rq)>,

    /// Inbound requests received from remote, waiting for an outbound response.
    pending_responses_for_inbound: HashMap<ConnectionId, Vec<RequestId>>,
    /// Outbound request sent to remote, waiting for an inbound response.
    pending_responses_for_outbound: HashMap<ConnectionId, Vec<RequestId>>,

    // Approved outbound requests for peers that are currently not connected, but a BehaviourAction::RequireDialAttempt
    // has been issued.
    awaiting_connection: HashMap<PeerId, SmallVec<[RequestId; 10]>>,
    // Pending requests for peers that don't have any firewall rules and currently await the response for a
    // FirewallRequest::PeerSpecificRule that has been sent.
    awaiting_peer_rule: HashMap<PeerId, HashMap<RequestDirection, SmallVec<[RequestId; 10]>>>,
    // Pending requests that require explicit approval due to Rule::Ask, and currently await the response for a
    // FirewallRequest::RequestApproval that has been sent.
    awaiting_approval: SmallVec<[(RequestId, RequestDirection); 10]>,

    // Actions that should be emitted by the NetBehaviour as NetworkBehaviourAction.
    actions: VecDeque<BehaviourAction<Rq, Rs>>,
}

impl<Rq, Rs> RequestManager<Rq, Rs> {
    pub fn new() -> Self {
        RequestManager {
            inbound_requests_cache: HashMap::new(),
            outbound_requests_cache: HashMap::new(),
            established_connections: HashMap::new(),
            pending_responses_for_inbound: HashMap::new(),
            pending_responses_for_outbound: HashMap::new(),
            awaiting_connection: HashMap::new(),
            awaiting_peer_rule: HashMap::new(),
            awaiting_approval: SmallVec::new(),
            actions: VecDeque::new(),
        }
    }

    // List of peers to which at least one connection is currently established.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.established_connections.keys().copied().collect()
    }

    // Currently established connections.
    pub fn established_connections(&self) -> Vec<(PeerId, EstablishedConnections)> {
        self.established_connections
            .iter()
            .map(|(p, c)| (*p, c.clone()))
            .collect()
    }

    // New outbound request that should be sent.
    // Depending on the approval and connection status, the appropriate [`BehaviourAction`] will be issued
    // and/ or the request will be cached if it is waiting for approval or connection.
    pub fn on_new_out_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: Rq,
        approval_status: ApprovalStatus,
    ) {
        match approval_status {
            ApprovalStatus::MissingRule => {
                // Add request to the list of requests that are awaiting a rule for that peer.
                self.outbound_requests_cache.insert(request_id, (peer, request));
                let await_rule = self.awaiting_peer_rule.entry(peer).or_default();
                await_rule
                    .entry(RequestDirection::Outbound)
                    .or_default()
                    .push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                // Add request to the list of requests that are awaiting individual approval.
                self.outbound_requests_cache.insert(request_id, (peer, request));
                self.awaiting_approval.push((request_id, RequestDirection::Outbound));
            }
            ApprovalStatus::Approved => {
                // Request is ready to be send if a connection exists.
                // If no connection to the peer exists, add dial attempt.
                if let Some(connection) = self.add_request(&peer, request_id, None, &RequestDirection::Outbound) {
                    // Request is approved and assigned to an existing connection.
                    let action = BehaviourAction::OutboundOk {
                        request_id,
                        peer,
                        request,
                        connection,
                    };
                    self.actions.push_back(action)
                } else {
                    self.outbound_requests_cache.insert(request_id, (peer, request));
                    self.add_dial_attempt(peer, request_id);
                }
            }
            ApprovalStatus::Rejected => {
                let action = BehaviourAction::OutboundFailure {
                    peer,
                    request_id,
                    failure: OutboundFailure::NotPermitted,
                };
                self.actions.push_back(action);
            }
        }
    }

    // New inbound request that was received.
    // Depending on the approval and connection status, the appropriate [`BehaviourAction`] will be issued
    // and/ or the request will be cached if it is waiting for approval.
    pub fn on_new_in_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: Rq,
        response_tx: oneshot::Sender<Rs>,
        connection: ConnectionId,
        approval_status: ApprovalStatus,
    ) {
        if !matches!(approval_status, ApprovalStatus::Rejected) {
            // Add request to the requests of the associated connection.
            // Return if the connection closed.
            let conn = self.add_request(&peer, request_id, Some(connection), &RequestDirection::Inbound);
            if conn.is_none() {
                let action = BehaviourAction::InboundFailure {
                    request_id,
                    peer,
                    failure: InboundFailure::ConnectionClosed,
                };
                self.actions.push_back(action);
                return;
            }
        }
        match approval_status {
            ApprovalStatus::MissingRule => {
                // Add request to the list of requests that are awaiting a rule for that peer.
                self.inbound_requests_cache
                    .insert(request_id, (peer, request, response_tx));
                let await_rule = self.awaiting_peer_rule.entry(peer).or_default();
                await_rule
                    .entry(RequestDirection::Inbound)
                    .or_default()
                    .push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                // Add request to the list of requests that are awaiting individual approval.
                self.inbound_requests_cache
                    .insert(request_id, (peer, request, response_tx));
                self.awaiting_approval.push((request_id, RequestDirection::Inbound));
            }
            ApprovalStatus::Approved => {
                let action = BehaviourAction::InboundOk {
                    request_id,
                    peer,
                    request,
                    response_tx,
                };
                self.actions.push_back(action);
            }
            ApprovalStatus::Rejected => {
                let action = BehaviourAction::InboundFailure {
                    request_id,
                    peer,
                    failure: InboundFailure::NotPermitted,
                };
                self.actions.push_back(action);
            }
        }
    }

    // Handle a new connection to a remote peer.
    pub fn on_connection_established(&mut self, peer: PeerId, id: ConnectionId, point: ConnectedPoint) {
        let is_first_connection = self
            .established_connections
            .get(&peer)
            .map(|established| established.connections.is_empty())
            .unwrap_or(true);
        self.established_connections
            .entry(peer)
            .or_default()
            .connections
            .insert(id, point);
        if !is_first_connection {
            return;
        }

        // Assign pending request to a connection and mark them as ready.
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                let (peer, request) = unwrap_or_return!(self.outbound_requests_cache.remove(&request_id));
                let connection = self
                    .add_request(&peer, request_id, None, &RequestDirection::Outbound)
                    .expect("Peer is connected");
                let action = BehaviourAction::OutboundOk {
                    request_id,
                    peer,
                    request,
                    connection,
                };
                self.actions.push_back(action);
            });
        }
    }

    // Handle an individual connection closing.
    // Emit failures for the pending responses on that connection.
    pub fn on_connection_closed(&mut self, peer: PeerId, connection: &ConnectionId, remaining_established: usize) {
        if remaining_established == 0 {
            self.established_connections.remove(&peer);
        } else {
            self.established_connections
                .entry(peer)
                .and_modify(|established| established.connections.retain(|id, _| id != connection));
        }

        for request_id in self
            .pending_responses_for_outbound
            .remove(connection)
            .unwrap_or_default()
        {
            self.actions.push_back(BehaviourAction::OutboundFailure {
                request_id,
                peer,
                failure: OutboundFailure::ConnectionClosed,
            })
        }

        for request_id in self
            .pending_responses_for_inbound
            .remove(connection)
            .unwrap_or_default()
        {
            // Remove request from all queues and lists.
            self.awaiting_approval.retain(|(r, _)| r != &request_id);
            if let Some(requests) = self
                .awaiting_peer_rule
                .get_mut(&peer)
                .and_then(|r| r.get_mut(&RequestDirection::Inbound))
            {
                requests.retain(|r| r != &request_id)
            }
            self.actions.push_back(BehaviourAction::InboundFailure {
                request_id,
                peer,
                failure: InboundFailure::ConnectionClosed,
            })
        }
    }

    // Handle a failed connection attempt to a currently not connected peer.
    // Emit failures for outbound requests that are awaiting the connection.
    pub fn on_dial_failure(&mut self, peer: PeerId) {
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                unwrap_or_return!(self.outbound_requests_cache.remove(&request_id));
                let action = BehaviourAction::OutboundFailure {
                    request_id,
                    peer,
                    failure: OutboundFailure::DialFailure,
                };
                self.actions.push_back(action);
            });
        }
    }

    // Update the endpoint of a connection.
    pub fn on_address_change(&mut self, peer: PeerId, connection: ConnectionId, new: ConnectedPoint) {
        self.established_connections
            .entry(peer)
            .or_default()
            .connections
            .entry(connection)
            .and_modify(|e| *e = new);
    }

    // Handle pending requests for a newly received rule.
    // Emit necessary 'BehaviourEvents' depending on rules and direction.
    // The method return the requests for which the `NetBehaviour` should query a `FirewallRequest::RequestApproval`.
    pub fn on_peer_rule<TRq: FwRequest<Rq>>(
        &mut self,
        peer: PeerId,
        rules: FirewallRules<TRq>,
        direction: RuleDirection,
    ) -> Option<Vec<(RequestId, TRq, RequestDirection)>> {
        let mut await_rule = self.awaiting_peer_rule.remove(&peer)?;
        // Affected requests.
        let mut requests = vec![];
        if direction.is_inbound() {
            if let Some(in_rqs) = await_rule.remove(&RequestDirection::Inbound) {
                requests.extend(in_rqs.into_iter().map(|rq| (rq, RequestDirection::Inbound)));
            }
        }
        if direction.is_outbound() {
            if let Some(out_rqs) = await_rule.remove(&RequestDirection::Outbound) {
                requests.extend(out_rqs.into_iter().map(|rq| (rq, RequestDirection::Outbound)));
            }
        }
        // Handle the requests according to the new rule.
        let require_ask = requests
            .into_iter()
            .filter_map(|(request_id, dir)| {
                let rule = match dir {
                    RequestDirection::Inbound => rules.inbound.as_ref(),
                    RequestDirection::Outbound => rules.outbound.as_ref(),
                };
                match rule {
                    Some(Rule::Ask) => {
                        // Requests need to await individual approval.
                        let rq = self.get_request_value_ref(&request_id, &dir)?;
                        self.awaiting_approval.push((request_id, dir.clone()));
                        Some((request_id, rq, dir))
                    }
                    Some(Rule::AllowAll) => {
                        self.handle_request_approval(request_id, &dir, true);
                        None
                    }
                    Some(Rule::RejectAll) => {
                        self.handle_request_approval(request_id, &dir, false);
                        None
                    }
                    Some(Rule::Restricted { restriction, .. }) => {
                        // Checking the individual restriction for the request.
                        if let Some(rq) = self.get_request_value_ref(&request_id, &dir) {
                            let is_allowed = restriction(&rq);
                            self.handle_request_approval(request_id, &dir, is_allowed);
                        }
                        None
                    }
                    None => {
                        // Reject request if no rule was provided.
                        self.handle_request_approval(request_id, &dir, false);
                        None
                    }
                }
            })
            .collect();
        // Keep unaffected requests in map.
        if !await_rule.is_empty() {
            self.awaiting_peer_rule.insert(peer, await_rule);
        }
        Some(require_ask)
    }

    // Handle the approval of an individual request.
    pub fn on_request_approval(&mut self, request_id: RequestId, is_allowed: bool) -> Option<()> {
        let index = self
            .awaiting_approval
            .binary_search_by(|(id, _)| id.cmp(&request_id))
            .ok()?;
        let (request_id, direction) = self.awaiting_approval.remove(index);
        self.handle_request_approval(request_id, &direction, is_allowed)
    }

    // Handle response / failure for a previously received request.
    // Remove the request from the list of pending responses, add failure if there is one.
    pub fn on_res_for_inbound(&mut self, peer: PeerId, request_id: RequestId, result: Result<(), InboundFailure>) {
        self.pending_responses_for_inbound
            .values_mut()
            .for_each(|pending| pending.retain(|id| id != &request_id));

        if let Err(failure) = result {
            let action = BehaviourAction::InboundFailure {
                peer,
                request_id,
                failure,
            };
            self.actions.push_back(action)
        }
    }

    // Handle response / failure for a previously sent request.
    // Remove the request from the list of pending responses.
    pub fn on_res_for_outbound(&mut self, peer: PeerId, request_id: RequestId, result: Result<Rs, OutboundFailure>) {
        self.pending_responses_for_outbound
            .values_mut()
            .for_each(|pending| pending.retain(|id| id != &request_id));

        let action = match result {
            Ok(response) => BehaviourAction::OutboundReceivedRes {
                request_id,
                peer,
                response,
            },
            Err(failure) => BehaviourAction::OutboundFailure {
                request_id,
                peer,
                failure,
            },
        };
        self.actions.push_back(action)
    }

    // Check if there are pending requests for rules for a specific peer.
    pub fn is_rule_request_pending(&self, peer: &PeerId) -> bool {
        self.awaiting_peer_rule.get(peer).is_some()
    }

    // Add a placeholder to the map of pending rule requests to mark that there is one for this peer.
    pub fn add_pending_rule_request(&mut self, peer: PeerId) {
        self.awaiting_peer_rule.entry(peer).or_insert_with(HashMap::new);
    }

    // Add a [`BehaviourAction::SetProtocolSupport`] to the action queue to inform the `Handler` of changed
    // protocol support.
    pub fn set_protocol_support(
        &mut self,
        peer: PeerId,
        connection: Option<ConnectionId>,
        protocol_support: ProtocolSupport,
    ) {
        let connections = connection
            .map(|c| vec![c])
            .or_else(|| {
                self.established_connections
                    .get(&peer)
                    .map(|est| est.connections.keys().into_iter().cloned().collect())
            })
            .unwrap_or_default();
        for conn in connections {
            self.actions.push_back(BehaviourAction::SetProtocolSupport {
                peer,
                connection: conn,
                support: protocol_support.clone(),
            });
        }
    }

    // Remove the next `BehaviourAction` from the queue and return it.
    pub fn take_next_action(&mut self) -> Option<BehaviourAction<Rq, Rs>> {
        let next = self.actions.pop_front();
        if self.actions.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.actions.shrink_to_fit();
        }
        next
    }

    // Add a [`BehaviourAction::RequireDialAttempt`] to the action queue to demand a dial attempt to the remote.
    fn add_dial_attempt(&mut self, peer: PeerId, request_id: RequestId) {
        let reqs = self.awaiting_connection.entry(peer).or_default();
        reqs.push(request_id);
        self.actions.push_back(BehaviourAction::RequireDialAttempt(peer));
    }

    // Handle the approval / rejection of a individual request.
    fn handle_request_approval(
        &mut self,
        request_id: RequestId,
        direction: &RequestDirection,
        is_allowed: bool,
    ) -> Option<()> {
        self.awaiting_approval.retain(|(r, _)| r != &request_id);
        let action = match direction {
            RequestDirection::Inbound => {
                let (peer, request, response_tx) = self.inbound_requests_cache.remove(&request_id)?;
                if !is_allowed {
                    let pending = match direction {
                        RequestDirection::Inbound => self.pending_responses_for_inbound.values_mut(),
                        RequestDirection::Outbound => self.pending_responses_for_outbound.values_mut(),
                    };
                    pending.for_each(|p| p.retain(|id| id != &request_id));
                    BehaviourAction::InboundFailure {
                        request_id,
                        peer,
                        failure: InboundFailure::NotPermitted,
                    }
                } else {
                    BehaviourAction::InboundOk {
                        request_id,
                        peer,
                        request,
                        response_tx,
                    }
                }
            }
            RequestDirection::Outbound => {
                let peer = self.outbound_requests_cache.get(&request_id).map(|(p, _)| *p)?;
                if !is_allowed {
                    self.outbound_requests_cache.remove(&request_id)?;
                    BehaviourAction::OutboundFailure {
                        request_id,
                        peer,
                        failure: OutboundFailure::NotPermitted,
                    }
                } else if let Some(connection) = self.add_request(&peer, request_id, None, &RequestDirection::Outbound)
                {
                    let (peer, request) = self.outbound_requests_cache.remove(&request_id)?;
                    BehaviourAction::OutboundOk {
                        request_id,
                        peer,
                        request,
                        connection,
                    }
                } else {
                    self.awaiting_connection.entry(peer).or_default().push(request_id);
                    BehaviourAction::RequireDialAttempt(peer)
                }
            }
        };
        self.actions.push_back(action);
        Some(())
    }

    // Get the request type of a store request.
    fn get_request_value_ref<TRq: FwRequest<Rq>>(&self, request_id: &RequestId, dir: &RequestDirection) -> Option<TRq> {
        let request = match dir {
            RequestDirection::Inbound => self.inbound_requests_cache.get(request_id).map(|(_, rq, _)| rq),
            RequestDirection::Outbound => self.outbound_requests_cache.get(request_id).map(|(_, rq)| rq),
        };
        request.map(|rq| TRq::from_request(rq))
    }

    // New request that has been sent/ received, but with no response yet.
    // Assign the request to the provided connection or else to a random established one.
    // Return [`None`] if there are no connections.
    fn add_request(
        &mut self,
        peer: &PeerId,
        request_id: RequestId,
        connection: Option<ConnectionId>,
        direction: &RequestDirection,
    ) -> Option<ConnectionId> {
        let connections = self.established_connections.get(peer)?.connections.keys();
        let conn = match connection {
            Some(conn) => {
                // Check if the provided connection is active.
                connections.into_iter().find(|&c| c == &conn)?;
                conn
            }
            None => {
                // Assign request to a rather random connection.
                let index = (request_id.value() as usize) % connections.len();
                #[allow(clippy::iter_skip_next)]
                connections.skip(index).next().cloned()?
            }
        };
        let map = match direction {
            RequestDirection::Inbound => &mut self.pending_responses_for_inbound,
            RequestDirection::Outbound => &mut self.pending_responses_for_outbound,
        };
        map.entry(conn).or_default().push(request_id);
        Some(conn)
    }
}

/// Information about the connection with a remote peer as maintained in the ConnectionManager.
#[derive(Clone, Debug)]
pub struct EstablishedConnections {
    /// Instant since which we are connected to the remote.
    pub start: Instant,
    /// List of connections and their connected point
    pub connections: HashMap<ConnectionId, ConnectedPoint>,
}

impl Default for EstablishedConnections {
    fn default() -> Self {
        EstablishedConnections {
            start: Instant::now(),
            connections: HashMap::new(),
        }
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{ProtocolSupport, EMPTY_QUEUE_SHRINK_THRESHOLD};
use crate::{
    firewall::{FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    unwrap_or_return, InboundFailure, OutboundFailure, RequestDirection, RequestId,
};
mod connections;
use connections::PeerConnectionManager;
use futures::channel::oneshot;
use libp2p::{core::connection::ConnectionId, PeerId};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};

// Actions for the behaviour to handle i.g. the behaviour emits the appropriate `NetworkBehaviourAction`.
pub(super) enum BehaviourAction<Rq, Rs> {
    // Inbound request / failures ready to be handled by the `NetBehaviour`.
    InboundReady {
        request_id: RequestId,
        peer: PeerId,
        result: Result<(Rq, oneshot::Sender<Rs>), InboundFailure>,
    },
    // Outbound request / failures ready to be handled by the `NetBehaviour`.
    // In case of `Result: Ok(..)`, the `ConnectionId` specifies the connection and handler that this request was
    // assigned to.
    OutboundReady {
        request_id: RequestId,
        peer: PeerId,
        result: Result<(Rq, ConnectionId), OutboundFailure>,
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
pub(super) enum ApprovalStatus {
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
pub(super) struct RequestManager<Rq, Rs, P>
where
    Rq: ToPermissionVariants<P>,
    P: VariantPermission,
{
    // Store of inbound requests that have not been approved yet.
    inbound_request_store: HashMap<RequestId, (PeerId, Rq, oneshot::Sender<Rs>)>,
    // Store of outbound requests that have not been approved, or where the target peer is not connected yet.
    outbound_request_store: HashMap<RequestId, (PeerId, Rq)>,
    // Currently established connections and the requests that have been send/received on the connection, but with no
    // response yet.
    connections: PeerConnectionManager,

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
    marker: PhantomData<P>,
}

impl<Rq, Rs, P> RequestManager<Rq, Rs, P>
where
    Rq: ToPermissionVariants<P>,
    P: VariantPermission,
{
    pub fn new() -> Self {
        RequestManager {
            inbound_request_store: HashMap::new(),
            outbound_request_store: HashMap::new(),
            connections: PeerConnectionManager::new(),
            awaiting_connection: HashMap::new(),
            awaiting_peer_rule: HashMap::new(),
            awaiting_approval: SmallVec::new(),
            actions: VecDeque::new(),
            marker: PhantomData,
        }
    }

    // List of peers to which at least one connection is currently established.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.get_connected_peers()
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
                self.outbound_request_store.insert(request_id, (peer, request));
                let await_rule = self.awaiting_peer_rule.entry(peer).or_default();
                await_rule
                    .entry(RequestDirection::Outbound)
                    .or_default()
                    .push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                // Add request to the list of requests that are awaiting individual approval.
                self.outbound_request_store.insert(request_id, (peer, request));
                self.awaiting_approval.push((request_id, RequestDirection::Outbound));
            }
            ApprovalStatus::Approved => {
                // Request is ready to be send if a connection exists.
                // If no connection to the peer exists, add dial attempt.
                if let Some(connection) =
                    self.connections
                        .add_request(&peer, request_id, None, &RequestDirection::Outbound)
                {
                    // Request is approved and assigned to an existing connection.
                    let action = BehaviourAction::OutboundReady {
                        request_id,
                        peer,
                        result: Ok((request, connection)),
                    };
                    self.actions.push_back(action)
                } else {
                    self.outbound_request_store.insert(request_id, (peer, request));
                    self.add_dial_attempt(peer, request_id);
                }
            }
            ApprovalStatus::Rejected => {
                let action = BehaviourAction::OutboundReady {
                    peer,
                    request_id,
                    result: Err(OutboundFailure::NotPermitted),
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
            let conn = self
                .connections
                .add_request(&peer, request_id, Some(connection), &RequestDirection::Inbound);
            if conn.is_none() {
                let action = BehaviourAction::InboundReady {
                    request_id,
                    peer,
                    result: Err(InboundFailure::ConnectionClosed),
                };
                self.actions.push_back(action);
                return;
            }
        }
        match approval_status {
            ApprovalStatus::MissingRule => {
                // Add request to the list of requests that are awaiting a rule for that peer.
                self.inbound_request_store
                    .insert(request_id, (peer, request, response_tx));
                let await_rule = self.awaiting_peer_rule.entry(peer).or_default();
                await_rule
                    .entry(RequestDirection::Inbound)
                    .or_default()
                    .push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                // Add request to the list of requests that are awaiting individual approval.
                self.inbound_request_store
                    .insert(request_id, (peer, request, response_tx));
                self.awaiting_approval.push((request_id, RequestDirection::Inbound));
            }
            ApprovalStatus::Approved => {
                let action = BehaviourAction::InboundReady {
                    request_id,
                    peer,
                    result: Ok((request, response_tx)),
                };
                self.actions.push_back(action);
            }
            ApprovalStatus::Rejected => {
                let action = BehaviourAction::InboundReady {
                    request_id,
                    peer,
                    result: Err(InboundFailure::NotPermitted),
                };
                self.actions.push_back(action);
            }
        }
    }

    // Handle a newly connected peer i.g. that at least one connection was established.
    // Assign pending request to a connection and mark them as ready.
    pub fn on_peer_connected(&mut self, peer: PeerId) {
        // Check that there is at least one active connection to the remote.
        if !self.connections.is_connected(&peer) {
            return;
        }
        // Handle pending requests
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                let (peer, request) = unwrap_or_return!(self.outbound_request_store.remove(&request_id));
                let connection = self
                    .connections
                    .add_request(&peer, request_id, None, &RequestDirection::Outbound)
                    .expect("Peer is connected");
                let action = BehaviourAction::OutboundReady {
                    request_id,
                    peer,
                    result: Ok((request, connection)),
                };
                self.actions.push_back(action);
            });
        }
    }

    // Handle a remote peer disconnecting completely.
    // Emit failures for the pending responses on all pending connections.
    pub fn on_peer_disconnected(&mut self, peer: PeerId) {
        if let Some(conns) = self.connections.remove_all_connections(&peer) {
            conns
                .iter()
                .for_each(|conn_id| self.on_connection_closed(peer, conn_id))
        }
    }

    // Handle a new individual connection to a remote peer.
    pub fn on_connection_established(&mut self, peer: PeerId, connection: ConnectionId) {
        self.connections.add_connection(peer, connection);
    }

    // Handle an individual connection closing.
    // Emit failures for the pending responses on that connection.
    pub fn on_connection_closed(&mut self, peer: PeerId, connection: &ConnectionId) {
        let pending_res = self.connections.remove_connection(peer, connection);
        if let Some(pending_res) = pending_res {
            for request_id in pending_res.outbound_requests {
                self.actions.push_back(BehaviourAction::OutboundReady {
                    request_id,
                    peer,
                    result: Err(OutboundFailure::ConnectionClosed),
                })
            }
            for request_id in pending_res.inbound_requests {
                // Remove request from all queues and lists.
                self.awaiting_approval.retain(|(r, _)| r != &request_id);
                if let Some(requests) = self
                    .awaiting_peer_rule
                    .get_mut(&peer)
                    .and_then(|r| r.get_mut(&RequestDirection::Inbound))
                {
                    requests.retain(|r| r != &request_id)
                }
                self.inbound_request_store.remove(&request_id);
                self.actions.push_back(BehaviourAction::InboundReady {
                    request_id,
                    peer,
                    result: Err(InboundFailure::ConnectionClosed),
                })
            }
        }
    }

    // Handle a failed connection attempt to a currently not connected peer.
    // Emit failures for outbound requests that are awaiting the connection.
    pub fn on_dial_failure(&mut self, peer: PeerId) {
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                unwrap_or_return!(self.outbound_request_store.remove(&request_id));
                let action = BehaviourAction::OutboundReady {
                    request_id,
                    peer,
                    result: Err(OutboundFailure::DialFailure),
                };
                self.actions.push_back(action);
            });
        }
    }

    // Handle pending requests for a newly received rule.
    // Emit necessary 'BehaviourEvents' depending on rules and direction.
    // The method return the requests for which the `NetBehaviour` should query a `FirewallRequest::RequestApproval`.
    pub fn on_peer_rule(
        &mut self,
        peer: PeerId,
        rules: FirewallRules,
        direction: RuleDirection,
    ) -> Option<Vec<(RequestId, P, RequestDirection)>> {
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
                    RequestDirection::Inbound => rules.inbound(),
                    RequestDirection::Outbound => rules.outbound(),
                };
                match rule {
                    Some(Rule::Ask) => {
                        // Requests need to await individual approval.
                        let rq = self.get_request_value_ref(&request_id, &dir)?;
                        let permissioned = rq.to_permissioned();
                        self.awaiting_approval.push((request_id, dir.clone()));
                        Some((request_id, permissioned, dir))
                    }
                    Some(Rule::Permission(permission)) => {
                        // Checking the individual permissions required for the request type.
                        if let Some(rq) = self.get_request_value_ref(&request_id, &dir) {
                            let is_allowed = permission.permits(&rq.permission_value());
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

    // Add failures for pending requests that are awaiting the peer rule.
    pub fn on_no_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        if let Some(mut await_rule) = self.awaiting_peer_rule.remove(&peer) {
            if direction.is_inbound() {
                if let Some(requests) = await_rule.remove(&RequestDirection::Inbound) {
                    for request_id in requests {
                        self.connections.remove_request(&request_id, &RequestDirection::Inbound);
                        unwrap_or_return!(self.inbound_request_store.remove(&request_id));
                        self.actions.push_back(BehaviourAction::InboundReady {
                            peer,
                            request_id,
                            result: Err(InboundFailure::NotPermitted),
                        });
                    }
                }
            }
            if direction.is_outbound() {
                if let Some(requests) = await_rule.remove(&RequestDirection::Outbound) {
                    for request_id in requests {
                        unwrap_or_return!(self.outbound_request_store.remove(&request_id));
                        self.actions.push_back(BehaviourAction::OutboundReady {
                            peer,
                            request_id,
                            result: Err(OutboundFailure::NotPermitted),
                        });
                    }
                }
            }
            // Keep unaffected requests in map.
            if !await_rule.is_empty() {
                self.awaiting_peer_rule.insert(peer, await_rule);
            }
        }
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
        self.connections.remove_request(&request_id, &RequestDirection::Inbound);
        if let Err(reason) = result {
            let action = BehaviourAction::InboundReady {
                peer,
                request_id,
                result: Err(reason),
            };
            self.actions.push_back(action)
        }
    }

    // Handle response / failure for a previously sent request.
    // Remove the request from the list of pending responses.
    pub fn on_res_for_outbound(&mut self, request_id: &RequestId) {
        self.connections.remove_request(request_id, &RequestDirection::Outbound);
    }

    // Check if there are pending requests for rules for a specific peer.
    pub fn pending_rule_requests(&self, peer: &PeerId) -> Option<RuleDirection> {
        let await_rule = self.awaiting_peer_rule.get(&peer)?;
        let is_inbound_pending = await_rule.contains_key(&RequestDirection::Inbound);
        let is_outbound_pending = await_rule.contains_key(&RequestDirection::Outbound);
        let is_both = is_inbound_pending && is_outbound_pending;
        is_both
            .then(|| RuleDirection::Both)
            .or_else(|| is_inbound_pending.then(|| RuleDirection::Inbound))
            .or_else(|| is_outbound_pending.then(|| RuleDirection::Outbound))
    }

    // Add a placeholder to the map of pending rule requests for the given direction to mark that there is a pending
    // rule request.
    pub fn add_pending_rule_requests(&mut self, peer: PeerId, direction: RuleDirection) {
        let pending = self.awaiting_peer_rule.entry(peer).or_insert_with(HashMap::new);
        if direction.is_inbound() && !pending.contains_key(&RequestDirection::Inbound) {
            pending.insert(RequestDirection::Inbound, SmallVec::new());
        }
        if direction.is_outbound() && !pending.contains_key(&RequestDirection::Outbound) {
            pending.insert(RequestDirection::Outbound, SmallVec::new());
        }
    }

    // Add a [`BehaviourAction::SetProtocolSupport`] to the action queue to inform the `ConnectionHandler` of changed
    // protocol support.
    pub fn set_protocol_support(
        &mut self,
        peer: PeerId,
        connection: Option<ConnectionId>,
        protocol_support: ProtocolSupport,
    ) {
        let connections = connection
            .map(|c| smallvec![c])
            .unwrap_or_else(|| self.connections.get_connections(&peer));
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
                let (peer, request, response_tx) = self.inbound_request_store.remove(&request_id)?;
                if !is_allowed {
                    self.connections.remove_request(&request_id, direction);
                    BehaviourAction::InboundReady {
                        request_id,
                        peer,
                        result: Err(InboundFailure::NotPermitted),
                    }
                } else {
                    BehaviourAction::InboundReady {
                        request_id,
                        peer,
                        result: Ok((request, response_tx)),
                    }
                }
            }
            RequestDirection::Outbound => {
                let peer = self.outbound_request_store.get(&request_id).map(|(p, _)| *p)?;
                if !is_allowed {
                    self.outbound_request_store.remove(&request_id)?;
                    BehaviourAction::OutboundReady {
                        request_id,
                        peer,
                        result: Err(OutboundFailure::NotPermitted),
                    }
                } else if let Some(connection) =
                    self.connections
                        .add_request(&peer, request_id, None, &RequestDirection::Outbound)
                {
                    let (peer, request) = self.outbound_request_store.remove(&request_id)?;
                    BehaviourAction::OutboundReady {
                        request_id,
                        peer,
                        result: Ok((request, connection)),
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
    fn get_request_value_ref(&self, request_id: &RequestId, dir: &RequestDirection) -> Option<&Rq> {
        match dir {
            RequestDirection::Inbound => self.inbound_request_store.get(request_id).map(|(_, rq, _)| rq),
            RequestDirection::Outbound => self.outbound_request_store.get(request_id).map(|(_, rq)| rq),
        }
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use self::connections::EstablishedConnections;
use super::{ProtocolSupport, EMPTY_QUEUE_SHRINK_THRESHOLD};
use crate::{
    firewall::{FirewallRules, Rule, RuleDirection},
    unwrap_or_return, InboundFailure, OutboundFailure, RequestDirection, RequestId,
};
mod connections;
use connections::PeerConnectionManager;
use futures::channel::oneshot;
use libp2p::{
    core::{connection::ConnectionId, ConnectedPoint},
    PeerId,
};
use smallvec::SmallVec;
use std::{
    borrow::Borrow,
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};

// Actions for the behaviour to handle i.g. the behaviour emits the appropriate `NetworkBehaviourAction`.
pub enum BehaviourAction<Rq, Rs> {
    // Approved inbound request to forward to the user.
    InboundOk {
        request_id: RequestId,
        peer: PeerId,
        request: Rq,
        response_tx: oneshot::Sender<Rs>,
    },
    // Failures on inbound requests
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    // Outbound request / failures ready to be handled by the `NetBehaviour`.
    // In case of `Result: Ok(..)`, the `ConnectionId` specifies the connection and handler that this request was
    // assigned to.
    OutboundOk {
        request_id: RequestId,
        peer: PeerId,
        request: Rq,
        connection: ConnectionId,
    },
    OutboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: OutboundFailure,
    },
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
pub struct RequestManager<Rq: Borrow<TRq>, Rs, TRq> {
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

    _marker: PhantomData<TRq>,
}

impl<Rq: Borrow<TRq>, Rs, TRq: Clone> RequestManager<Rq, Rs, TRq> {
    pub fn new() -> Self {
        RequestManager {
            inbound_request_store: HashMap::new(),
            outbound_request_store: HashMap::new(),
            connections: PeerConnectionManager::new(),
            awaiting_connection: HashMap::new(),
            awaiting_peer_rule: HashMap::new(),
            awaiting_approval: SmallVec::new(),
            actions: VecDeque::new(),
            _marker: PhantomData,
        }
    }

    // List of peers to which at least one connection is currently established.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.get_connected_peers()
    }

    // Currently established connections.
    pub fn get_established_connections(&self) -> Vec<(PeerId, EstablishedConnections)> {
        self.connections.get_all_connections()
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
                    let action = BehaviourAction::OutboundOk {
                        request_id,
                        peer,
                        request,
                        connection,
                    };
                    self.actions.push_back(action)
                } else {
                    self.outbound_request_store.insert(request_id, (peer, request));
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
            let conn = self
                .connections
                .add_request(&peer, request_id, Some(connection), &RequestDirection::Inbound);
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

    // Handle a remote peer disconnecting completely.
    // Emit failures for the pending responses on all pending connections.
    pub fn on_peer_disconnected(&mut self, peer: PeerId) {
        if let Some(established) = self.connections.remove_all_connections(&peer) {
            established
                .connections
                .keys()
                .into_iter()
                .for_each(|conn_id| self.on_connection_closed(peer, conn_id))
        }
    }

    // Handle a new individual connection to a remote peer.
    pub fn on_connection_established(&mut self, peer: PeerId, id: ConnectionId, point: ConnectedPoint) {
        self.connections.add_connection(peer, id, point);
    }

    // Handle an individual connection closing.
    // Emit failures for the pending responses on that connection.
    pub fn on_connection_closed(&mut self, peer: PeerId, connection: &ConnectionId) {
        let pending_res = self.connections.remove_connection(peer, connection);
        if let Some(pending_res) = pending_res {
            for request_id in pending_res.outbound_requests {
                self.actions.push_back(BehaviourAction::OutboundFailure {
                    request_id,
                    peer,
                    failure: OutboundFailure::ConnectionClosed,
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
                self.actions.push_back(BehaviourAction::InboundFailure {
                    request_id,
                    peer,
                    failure: InboundFailure::ConnectionClosed,
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
                let action = BehaviourAction::OutboundFailure {
                    request_id,
                    peer,
                    failure: OutboundFailure::DialFailure,
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
        self.connections.remove_request(&request_id, &RequestDirection::Inbound);
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
        self.connections
            .remove_request(&request_id, &RequestDirection::Outbound);
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

    // Add a [`BehaviourAction::SetProtocolSupport`] to the action queue to inform the `ConnectionHandler` of changed
    // protocol support.
    pub fn set_protocol_support(
        &mut self,
        peer: PeerId,
        connection: Option<ConnectionId>,
        protocol_support: ProtocolSupport,
    ) {
        let connections = connection
            .map(|c| vec![c])
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
                let peer = self.outbound_request_store.get(&request_id).map(|(p, _)| *p)?;
                if !is_allowed {
                    self.outbound_request_store.remove(&request_id)?;
                    BehaviourAction::OutboundFailure {
                        request_id,
                        peer,
                        failure: OutboundFailure::NotPermitted,
                    }
                } else if let Some(connection) =
                    self.connections
                        .add_request(&peer, request_id, None, &RequestDirection::Outbound)
                {
                    let (peer, request) = self.outbound_request_store.remove(&request_id)?;
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
    fn get_request_value_ref(&self, request_id: &RequestId, dir: &RequestDirection) -> Option<TRq> {
        let request = match dir {
            RequestDirection::Inbound => self.inbound_request_store.get(request_id).map(|(_, rq, _)| rq),
            RequestDirection::Outbound => self.outbound_request_store.get(request_id).map(|(_, rq)| rq),
        };
        request.map(|rq| rq.borrow().clone())
    }
}

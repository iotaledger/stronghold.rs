// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{
    firewall::{FirewallRules, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    unwrap_or_return, RecvResponseErr, RequestDirection, RequestId, RequestMessage, EMPTY_QUEUE_SHRINK_THRESHOLD,
};
mod connections;
use connections::{PeerConnectionManager, PendingResponses};
use libp2p::{core::connection::ConnectionId, PeerId};
use smallvec::SmallVec;
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};

#[doc(hidden)]
pub(super) enum BehaviourAction<Rq, Rs> {
    // The Outbound request was rejected due to firewall configuration.
    OutboundRejected {
        peer: PeerId,
        request_id: RequestId,
    },
    // Inbound request that was approved and should be emitted as Behaviour Event to the user.
    InboundReady {
        request_id: RequestId,
        peer: PeerId,
        request: RequestMessage<Rq, Rs>,
    },
    // Outbound request to a connected peer that was approved and that should be send to the handler of the connection
    // that this request was assigend to.
    OutboundReady {
        request_id: RequestId,
        peer: PeerId,
        connection: ConnectionId,
        request: RequestMessage<Rq, Rs>,
    },
    // Required dial attempt to connect a peer where at least one approved outbound request is pending.
    RequireDialAttempt(PeerId),
    // Firewall rules for a specific peer, that should be send to the handler.
    ReceivedPeerRules {
        peer: PeerId,
        // If a ConnectionId is provided, only the handler of that specific connection will be informed of the peer's
        // rules, otherwise all handlers of that peer will receive the new rules.
        connection: Option<ConnectionId>,
        rules: FirewallRules,
    },
    // Recieved the response/ result for a previously send request, that should be emitted as Behaviour Event to the
    // user.
    ReceivedResponse {
        peer: PeerId,
        request_id: RequestId,
        result: Result<(), RecvResponseErr>,
    },
}

#[doc(hidden)]
pub(super) enum ApprovalStatus {
    // Neither a peer specific, nor a default rule for the peer + direction exists.
    // A FirewallRequest::PeerSpecificRule has been send and the NetBehaviour currently awaits a response.
    MissingRule,
    // For the peer + direction, the Rule::Ask is set, which requires explicit approval.
    // The NetBehaviour sent a FirewallRequest::RequestApproval and currently awaits the approval.
    MissingApproval,
    Approved,
    Rejected,
}

#[doc(hidden)]
pub(super) struct RequestManager<Rq, Rs, P>
where
    Rq: ToPermissionVariants<P>,
    P: VariantPermission,
{
    // Cache of inbound requests that have not been approved yet.
    inbound_request_store: HashMap<RequestId, (PeerId, RequestMessage<Rq, Rs>)>,
    // Cache of outbound requests that have not been approved, or where the target peer is not connected yet.
    outbound_request_store: HashMap<RequestId, (PeerId, RequestMessage<Rq, Rs>)>,
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

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.connected_peers()
    }

    pub fn on_new_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
        approval_state: ApprovalStatus,
        direction: RequestDirection,
    ) {
        match approval_state {
            ApprovalStatus::MissingRule => {
                self.store_request(peer, request_id, request, &direction);
                let await_rule = self.awaiting_peer_rule.entry(peer).or_default();
                await_rule.entry(direction).or_default().push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                self.store_request(peer, request_id, request, &direction);
                self.awaiting_approval.push((request_id, direction));
            }
            ApprovalStatus::Approved => {
                if let Some(connection) = self.connections.on_new_request(&peer, request_id, &direction) {
                    self.add_ready_request(peer, request_id, connection, request, &direction);
                } else if let RequestDirection::Outbound = direction {
                    self.store_request(peer, request_id, request, &RequestDirection::Outbound);
                    self.add_dial_attempt(peer, request_id);
                }
            }
            ApprovalStatus::Rejected => {
                if let RequestDirection::Outbound = direction {
                    drop(request.response_tx);
                    self.actions
                        .push_back(BehaviourAction::OutboundRejected { peer, request_id });
                }
            }
        }
    }

    pub fn on_peer_connected(&mut self, peer: PeerId) {
        if !self.connections.is_connected(&peer) {
            return;
        }
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                let (peer, request) =
                    unwrap_or_return!(self.take_stored_request(&request_id, &RequestDirection::Outbound));
                let connection = self
                    .connections
                    .on_new_request(&peer, request_id, &RequestDirection::Outbound)
                    .expect("Peer is connected");
                let action = BehaviourAction::OutboundReady {
                    request_id,
                    peer,
                    connection,
                    request,
                };
                self.actions.push_back(action);
            });
        }
    }

    pub fn on_peer_disconnected(&mut self, peer: PeerId) {
        let pending_responses = self.connections.remove_all_connections(&peer);
        self.handle_connection_closed(peer, pending_responses);
    }

    pub fn on_connection_established(&mut self, peer: PeerId, connection: ConnectionId) {
        self.connections.add_connection(peer, connection);
    }

    pub fn on_connection_closed(&mut self, peer: PeerId, connection: &ConnectionId) {
        let pending_responses = self.connections.remove_connection(peer, connection);
        self.handle_connection_closed(peer, pending_responses);
    }

    pub fn on_dial_failure(&mut self, peer: PeerId) {
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                if let Some((_, req)) = self.take_stored_request(&request_id, &RequestDirection::Outbound) {
                    drop(req.response_tx);
                }
                let action = BehaviourAction::ReceivedResponse {
                    request_id,
                    peer,
                    result: Err(RecvResponseErr::DialFailure),
                };
                self.actions.push_back(action);
            });
        }
    }

    pub fn on_peer_rule(
        &mut self,
        peer: PeerId,
        rules: FirewallRules,
        direction: RuleDirection,
    ) -> Option<Vec<(RequestId, P, RequestDirection)>> {
        self.actions.push_back(BehaviourAction::ReceivedPeerRules {
            peer,
            connection: None,
            rules: rules.clone(),
        });
        let mut await_rule = self.awaiting_peer_rule.remove(&peer)?;
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
        let require_ask = requests
            .into_iter()
            .filter_map(|(request_id, dir)| {
                let rule = match dir {
                    RequestDirection::Inbound => rules.inbound(),
                    RequestDirection::Outbound => rules.outbound(),
                };
                match rule {
                    Some(Rule::Ask) => {
                        let rq = self.get_request_value_ref(&request_id)?;
                        let permissioned = rq.to_permissioned();
                        self.awaiting_approval.push((request_id, dir.clone()));
                        Some((request_id, permissioned, dir))
                    }
                    Some(Rule::Permission(permission)) => {
                        if let Some(rq) = self.get_request_value_ref(&request_id) {
                            let is_allowed = permission.permits(&rq.permission_value());
                            self.handle_request_approval(request_id, &dir, is_allowed);
                        }
                        None
                    }
                    None => {
                        self.handle_request_approval(request_id, &dir, false);
                        None
                    }
                }
            })
            .collect();
        if !await_rule.is_empty() {
            self.awaiting_peer_rule.insert(peer, await_rule);
        }
        Some(require_ask)
    }

    pub fn on_no_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        if let Some(mut await_rule) = self.awaiting_peer_rule.remove(&peer) {
            if direction.is_inbound() {
                if let Some(requests) = await_rule.remove(&RequestDirection::Inbound) {
                    for request_id in requests {
                        self.take_stored_request(&request_id, &RequestDirection::Inbound);
                    }
                }
            }
            if direction.is_outbound() {
                if let Some(requests) = await_rule.remove(&RequestDirection::Outbound) {
                    for request_id in requests {
                        self.take_stored_request(&request_id, &RequestDirection::Outbound);
                        self.actions
                            .push_back(BehaviourAction::OutboundRejected { peer, request_id });
                    }
                }
            }
            if !await_rule.is_empty() {
                self.awaiting_peer_rule.insert(peer, await_rule);
            }
        }
    }

    pub fn on_request_approval(&mut self, request_id: RequestId, is_allowed: bool) -> Option<()> {
        let index = self
            .awaiting_approval
            .binary_search_by(|(id, _)| id.cmp(&request_id))
            .ok()?;
        let (request_id, direction) = self.awaiting_approval.remove(index);
        self.handle_request_approval(request_id, &direction, is_allowed)
    }

    pub fn on_recv_res_for_inbound(&mut self, connection: &ConnectionId, request_id: &RequestId) {
        self.connections
            .remove_request(connection, request_id, &RequestDirection::Inbound);
    }

    pub fn on_recv_res_for_outbound(
        &mut self,
        peer: PeerId,
        connection: &ConnectionId,
        request_id: RequestId,
        result: Result<(), RecvResponseErr>,
    ) {
        self.connections
            .remove_request(connection, &request_id, &RequestDirection::Outbound);
        let action = BehaviourAction::ReceivedResponse {
            peer,
            request_id,
            result,
        };
        self.actions.push_back(action)
    }

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

    pub fn add_pending_rule_requests(&mut self, peer: PeerId, direction: RuleDirection) {
        let pending = self.awaiting_peer_rule.entry(peer).or_insert_with(HashMap::new);
        if direction.is_inbound() && !pending.contains_key(&RequestDirection::Inbound) {
            pending.insert(RequestDirection::Inbound, SmallVec::new());
        }
        if direction.is_outbound() && !pending.contains_key(&RequestDirection::Outbound) {
            pending.insert(RequestDirection::Outbound, SmallVec::new());
        }
    }

    pub fn push_action(&mut self, action: BehaviourAction<Rq, Rs>) {
        self.actions.push_back(action);
    }

    pub fn take_next_action(&mut self) -> Option<BehaviourAction<Rq, Rs>> {
        let next = self.actions.pop_front();
        if self.actions.capacity() > EMPTY_QUEUE_SHRINK_THRESHOLD {
            self.actions.shrink_to_fit();
        }
        next
    }

    fn store_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
        direction: &RequestDirection,
    ) {
        match direction {
            RequestDirection::Inbound => self.inbound_request_store.insert(request_id, (peer, request)),
            RequestDirection::Outbound => self.outbound_request_store.insert(request_id, (peer, request)),
        };
    }

    fn take_stored_request(
        &mut self,
        request_id: &RequestId,
        direction: &RequestDirection,
    ) -> Option<(PeerId, RequestMessage<Rq, Rs>)> {
        match direction {
            RequestDirection::Inbound => self.inbound_request_store.remove(request_id),
            RequestDirection::Outbound => self.outbound_request_store.remove(request_id),
        }
    }

    fn add_dial_attempt(&mut self, peer: PeerId, request_id: RequestId) {
        let reqs = self.awaiting_connection.entry(peer).or_default();
        reqs.push(request_id);
        self.actions.push_back(BehaviourAction::RequireDialAttempt(peer));
    }

    fn add_ready_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        connection: ConnectionId,
        request: RequestMessage<Rq, Rs>,
        direction: &RequestDirection,
    ) {
        let event = match direction {
            RequestDirection::Inbound => BehaviourAction::InboundReady {
                request_id,
                peer,
                request,
            },
            RequestDirection::Outbound => BehaviourAction::OutboundReady {
                request_id,
                peer,
                connection,
                request,
            },
        };
        self.actions.push_back(event)
    }

    fn handle_request_approval(
        &mut self,
        request_id: RequestId,
        direction: &RequestDirection,
        is_allowed: bool,
    ) -> Option<()> {
        if !is_allowed {
            let (peer, req) = self.take_stored_request(&request_id, direction)?;
            drop(req.response_tx);
            if let RequestDirection::Outbound = direction {
                self.actions
                    .push_back(BehaviourAction::OutboundRejected { request_id, peer })
            }
            return Some(());
        }
        let peer = *self.get_request_peer_ref(&request_id)?;
        if let Some(connection) = self.connections.on_new_request(&peer, request_id, &direction) {
            let (peer, request) = self.take_stored_request(&request_id, direction)?;
            self.add_ready_request(peer, request_id, connection, request, direction);
            Some(())
        } else {
            match direction {
                RequestDirection::Inbound => {
                    let (_, req) = self.take_stored_request(&request_id, direction)?;
                    drop(req.response_tx);
                }
                RequestDirection::Outbound => self.add_dial_attempt(peer, request_id),
            }
            Some(())
        }
    }

    fn handle_connection_closed(&mut self, peer: PeerId, pending_res: Option<PendingResponses>) {
        if let Some(pending_res) = pending_res {
            let closed = pending_res.outbound_requests.into_iter().map(|request_id| {
                let result = Err(RecvResponseErr::ConnectionClosed);
                BehaviourAction::ReceivedResponse {
                    request_id,
                    peer,
                    result,
                }
            });
            self.actions.extend(closed);
        }
    }

    fn get_request_peer_ref(&self, request_id: &RequestId) -> Option<&PeerId> {
        self.inbound_request_store
            .get(request_id)
            .or_else(|| self.outbound_request_store.get(request_id))
            .map(|(peer, _)| peer)
    }

    fn get_request_value_ref(&self, request_id: &RequestId) -> Option<&Rq> {
        self.inbound_request_store
            .get(request_id)
            .or_else(|| self.outbound_request_store.get(request_id))
            .map(|(_, query)| &query.data)
    }
}

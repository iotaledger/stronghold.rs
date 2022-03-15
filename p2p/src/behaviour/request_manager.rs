// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    behaviour::EMPTY_QUEUE_SHRINK_THRESHOLD,
    firewall::{FwRequest, Rule},
    unwrap_or_return, InboundFailure, OutboundFailure, RequestId,
};

use futures::channel::oneshot;
pub use libp2p::core::{connection::ConnectionId, ConnectedPoint};
use libp2p::PeerId;
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};

// Actions for the behaviour so that it emits the appropriate `NetworkBehaviourAction`.
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
    // Outbound request ready to be handled by the `NetworkBehaviour`.
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
    // Required dial attempt to connect a peer where at least one request is pending.
    RequireDialAttempt(PeerId),
    // Configure if the handler should support inbound requests.
    SetInboundSupport {
        peer: PeerId,
        // The target connection.
        // For each `ConnectionId`, a separate handler is running.
        connection: ConnectionId,
        support: bool,
    },
}

// The status of a new request according to the firewall rule of the associated peer.
#[derive(Debug)]
pub enum ApprovalStatus {
    // Neither a peer specific, nor a default rule for the peer exists.
    // A FirewallRequest::PeerSpecificRule has been send and the `NetworkBehaviour` currently awaits a response.
    MissingRule,
    // For the peer, the Rule::Ask is set, which requires explicit approval.
    // The `NetworkBehaviour` sent a `FirewallRequest::RequestApproval` and currently awaits the approval.
    MissingApproval,
    // The request is approved by the current firewall rule.
    Approved,
    // The request is rejected by the current firewall rule.
    Rejected,
}

// Direction of a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RequestDirection {
    Inbound,
    Outbound,
}

// Manager for pending requests that are awaiting a peer rule, individual approval, or a connection to the remote.
//
// Stores pending requests, manages rule, approval and connection changes, and queues required `BehaviourAction`s for
// the `NetworkBehaviour` to handle.
#[derive(Default)]
pub struct RequestManager<Rq, Rs> {
    // Currently active connections for each peer.
    established_connections: HashMap<PeerId, HashMap<ConnectionId, ConnectedPoint>>,

    // Cache of inbound requests that have not been approved yet.
    inbound_requests_cache: HashMap<RequestId, (PeerId, Rq, oneshot::Sender<Rs>)>,
    // Cache of outbound requests where the target peer is not connected yet.
    outbound_requests_cache: HashMap<RequestId, (PeerId, Rq)>,

    /// Inbound requests received on each connection, where no response was sent yet.
    inbound_requests_on_connection: HashMap<ConnectionId, Vec<RequestId>>,
    /// Outbound requests sent on each connection, where no response was received yet.
    outbound_requests_on_connection: HashMap<ConnectionId, Vec<RequestId>>,

    // Outbound requests for peers that are currently not connected, but a BehaviourAction::RequireDialAttempt
    // has been issued.
    awaiting_connection: HashMap<PeerId, SmallVec<[RequestId; 10]>>,
    // Pending inbound requests for peers that don't have any a firewall rule and currently await the response for a
    // `FirewallRequest::PeerSpecificRule` that has been sent.
    awaiting_peer_rule: HashMap<PeerId, SmallVec<[RequestId; 10]>>,
    // Pending inbound requests that require explicit approval due to Rule::Ask, and currently await the response for a
    // `FirewallRequest::RequestApproval` that has been sent.
    awaiting_approval: SmallVec<[RequestId; 10]>,

    // Actions that should be emitted by the `NetworkBehaviour` as `NetworkBehaviourAction`.
    actions: VecDeque<BehaviourAction<Rq, Rs>>,
}

impl<Rq, Rs> RequestManager<Rq, Rs> {
    pub fn new() -> Self {
        RequestManager {
            inbound_requests_cache: HashMap::new(),
            outbound_requests_cache: HashMap::new(),
            established_connections: HashMap::new(),
            inbound_requests_on_connection: HashMap::new(),
            outbound_requests_on_connection: HashMap::new(),
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
    pub fn established_connections(&self) -> Vec<(PeerId, Vec<ConnectedPoint>)> {
        self.established_connections
            .iter()
            .map(|(p, c)| (*p, c.values().cloned().collect()))
            .collect()
    }

    // New outbound request that should be sent.
    // If the remote is connected the request is assigned to a connection, else it is cached and a
    // new connection attempt is issued.
    pub fn on_new_out_request(&mut self, peer: PeerId, request_id: RequestId, request: Rq) {
        // If no connection to the peer exists, add dial attempt.
        if let Some(connection) =
            self.assign_request_to_connection(&peer, request_id, None, &RequestDirection::Outbound)
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
            self.outbound_requests_cache.insert(request_id, (peer, request));
            let reqs = self.awaiting_connection.entry(peer).or_default();
            reqs.push(request_id);
            self.actions.push_back(BehaviourAction::RequireDialAttempt(peer));
        }
    }

    // New inbound request was received.
    // Depending on the approval status it is either directly approved/ rejected, or cached
    // while it is waiting for peer rules or individual approval of the request.
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
            let conn =
                self.assign_request_to_connection(&peer, request_id, Some(connection), &RequestDirection::Inbound);
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
                self.awaiting_peer_rule.entry(peer).or_default().push(request_id);
            }
            ApprovalStatus::MissingApproval => {
                // Add request to the list of requests that are awaiting individual approval.
                self.inbound_requests_cache
                    .insert(request_id, (peer, request, response_tx));
                self.awaiting_approval.push(request_id);
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
            .map(|connections| connections.is_empty())
            .unwrap_or(true);
        self.established_connections.entry(peer).or_default().insert(id, point);
        if !is_first_connection {
            return;
        }

        // Assign pending requests to the new connection and mark them as ready.
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            requests.into_iter().for_each(|request_id| {
                let (peer, request) = unwrap_or_return!(self.outbound_requests_cache.remove(&request_id));
                let connection = self
                    .assign_request_to_connection(&peer, request_id, Some(id), &RequestDirection::Outbound)
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
    // Emit failures for the pending requests on that connection.
    pub fn on_connection_closed(&mut self, peer: PeerId, connection: &ConnectionId, remaining_established: usize) {
        if remaining_established == 0 {
            self.established_connections.remove(&peer);
        } else {
            self.established_connections
                .entry(peer)
                .and_modify(|connections| connections.retain(|id, _| id != connection));
        }

        for request_id in self
            .outbound_requests_on_connection
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
            .inbound_requests_on_connection
            .remove(connection)
            .unwrap_or_default()
        {
            // Remove request from all queues and lists.
            self.awaiting_approval.retain(|r| r != &request_id);
            if let Some(requests) = self.awaiting_peer_rule.get_mut(&peer) {
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
        let requests = unwrap_or_return!(self.awaiting_connection.remove(&peer));
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

    // Update the endpoint of a connection.
    pub fn on_address_change(&mut self, peer: PeerId, connection: ConnectionId, new: ConnectedPoint) {
        self.established_connections
            .entry(peer)
            .or_default()
            .entry(connection)
            .and_modify(|e| *e = new);
    }

    // Update the status of the requests that are awaiting the rule. Depending on the rule,
    // this either directly approved / rejects requests, or in case of `Rule::Ask` it returns
    // the list of pending requests, for which now a a `FirewallRequest::RequestApproval` is needed.
    pub fn on_peer_rule<TRq: FwRequest<Rq>>(
        &mut self,
        peer: PeerId,
        rule: Option<Rule<TRq>>,
    ) -> Option<Vec<(RequestId, TRq)>> {
        // Affected requests.
        let requests = self.awaiting_peer_rule.remove(&peer)?;
        if requests.is_empty() {
            return None;
        }
        // Handle the requests according to the new rule.
        let require_ask = requests
            .into_iter()
            .filter_map(|request_id| {
                match &rule {
                    Some(Rule::Ask) => {
                        // Request needs to await individual approval.
                        let rq = self
                            .inbound_requests_cache
                            .get(&request_id)
                            .map(|(_, rq, _)| TRq::from_request(rq))?;
                        self.awaiting_approval.push(request_id);
                        Some((request_id, rq))
                    }
                    Some(Rule::AllowAll) => {
                        self.on_request_approval(request_id, true);
                        None
                    }
                    Some(Rule::RejectAll) => {
                        self.on_request_approval(request_id, false);
                        None
                    }
                    Some(Rule::Restricted { restriction, .. }) => {
                        // Checking the individual restriction for the request.
                        if let Some(rq) = self
                            .inbound_requests_cache
                            .get(&request_id)
                            .map(|(_, rq, _)| TRq::from_request(rq))
                        {
                            let is_allowed = restriction(&rq);
                            self.on_request_approval(request_id, is_allowed);
                        }
                        None
                    }
                    None => {
                        // Reject request if no rule was provided.
                        self.on_request_approval(request_id, false);
                        None
                    }
                }
            })
            .collect();
        Some(require_ask)
    }

    // Handle the approval of an individual request.
    pub fn on_request_approval(&mut self, request_id: RequestId, is_allowed: bool) {
        self.awaiting_approval.retain(|r| r != &request_id);
        let (peer, request, response_tx) = unwrap_or_return!(self.inbound_requests_cache.remove(&request_id));
        let action = if is_allowed {
            BehaviourAction::InboundOk {
                request_id,
                peer,
                request,
                response_tx,
            }
        } else {
            self.inbound_requests_on_connection
                .iter_mut()
                .for_each(|(_, pending)| pending.retain(|r| r != &request_id));
            BehaviourAction::InboundFailure {
                request_id,
                peer,
                failure: InboundFailure::NotPermitted,
            }
        };
        self.actions.push_back(action);
    }

    // Handle response / failure for a previously received request.
    pub fn on_res_for_inbound(&mut self, peer: PeerId, request_id: RequestId, result: Result<(), InboundFailure>) {
        self.inbound_requests_on_connection
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
    pub fn on_res_for_outbound(&mut self, peer: PeerId, request_id: RequestId, result: Result<Rs, OutboundFailure>) {
        self.outbound_requests_on_connection
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

    // Check if there are pending requests for rule for a specific peer.
    pub fn is_rule_request_pending(&self, peer: &PeerId) -> bool {
        self.awaiting_peer_rule.get(peer).is_some()
    }

    // Add a placeholder to the map of pending rule requests to mark that there is one for this peer.
    pub fn add_pending_rule_request(&mut self, peer: PeerId) {
        self.awaiting_peer_rule.entry(peer).or_insert_with(SmallVec::new);
    }

    // Add a `BehaviourAction::SetProtocolSupport` to the action queue to inform the `Handler` of changed
    // protocol support.
    pub fn set_inbound_support(&mut self, peer: PeerId, connection: Option<ConnectionId>, inbound_support: bool) {
        let connections = connection
            .map(|c| vec![c])
            .or_else(|| {
                self.established_connections
                    .get(&peer)
                    .map(|connections| connections.keys().into_iter().cloned().collect())
            })
            .unwrap_or_default();
        for conn in connections {
            self.actions.push_back(BehaviourAction::SetInboundSupport {
                peer,
                connection: conn,
                support: inbound_support,
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

    // New request that has been sent/ received, but with no response yet.
    // Assign the request to the given connection or else to a random established one.
    // Return `None` if there are no connections.
    fn assign_request_to_connection(
        &mut self,
        peer: &PeerId,
        request_id: RequestId,
        connection: Option<ConnectionId>,
        direction: &RequestDirection,
    ) -> Option<ConnectionId> {
        let mut connections = self.established_connections.get(peer)?.keys();
        let conn = match connection {
            Some(conn) => {
                // Check if the provided connection is active.
                connections.into_iter().find(|&c| c == &conn)?;
                conn
            }
            None => {
                // Assign request to a rather random connection.
                let index = (request_id.value() as usize) % connections.len();
                connections.nth(index).cloned()?
            }
        };
        let map = match direction {
            RequestDirection::Inbound => &mut self.inbound_requests_on_connection,
            RequestDirection::Outbound => &mut self.outbound_requests_on_connection,
        };
        map.entry(conn).or_default().push(request_id);
        Some(conn)
    }
}

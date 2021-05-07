// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

pub mod firewall;
#[doc(hidden)]
mod handler;
#[doc(hidden)]
mod request_manager;
#[doc(hidden)]
mod types;
use self::firewall::{FirewallRules, RuleDirection};
use super::unwrap_or_return;
use firewall::{FirewallConfiguration, FirewallRequest, Rule, ToPermissionVariants, VariantPermission};
use futures::{
    channel::{
        mpsc::{self, SendError},
        oneshot,
    },
    future::{poll_fn, BoxFuture},
    stream::FuturesUnordered,
    task::{Context, Poll},
    FutureExt, StreamExt, TryFutureExt,
};
pub use handler::CommunicationProtocol;
use handler::ConnectionHandler;
use libp2p::{
    core::{
        connection::{ConnectionId, ListenerId},
        either::EitherOutput,
        ConnectedPoint, Multiaddr, PeerId,
    },
    mdns::Mdns,
    relay::Relay,
    swarm::{
        DialPeerCondition, IntoProtocolsHandler, IntoProtocolsHandlerSelect, NetworkBehaviour, NetworkBehaviourAction,
        NotifyHandler, PollParameters, ProtocolsHandler,
    },
};
use request_manager::{ApprovalStatus, BehaviourAction, RequestManager};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::HashMap,
    error,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};
pub use types::*;

type NetworkAction<Proto> = NetworkBehaviourAction<
    <<<Proto as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <Proto as NetworkBehaviour>::OutEvent,
>;

type MdnsRelayProtocolsHandler = IntoProtocolsHandlerSelect<
    <Mdns as NetworkBehaviour>::ProtocolsHandler,
    <Relay as NetworkBehaviour>::ProtocolsHandler,
>;

pub type PendingPeerRuleRequest = BoxFuture<'static, (PeerId, RuleDirection, Option<FirewallRules>)>;
pub type PendingApprovalRequest = BoxFuture<'static, (RequestId, bool)>;

const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

#[derive(Debug)]
pub struct NetBehaviourConfig {
    pub supported_protocols: SmallVec<[CommunicationProtocol; 2]>,
    pub request_timeout: Duration,
    pub connection_timeout: Duration,
    pub firewall: FirewallConfiguration,
}

impl Default for NetBehaviourConfig {
    fn default() -> Self {
        Self {
            supported_protocols: smallvec![CommunicationProtocol],
            connection_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            firewall: FirewallConfiguration::default(),
        }
    }
}

pub struct NetBehaviour<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    relay: Relay,

    supported_protocols: SmallVec<[CommunicationProtocol; 2]>,
    request_timeout: Duration,
    connection_timeout: Duration,

    next_request_id: RequestId,
    next_inbound_id: Arc<AtomicU64>,

    request_manager: RequestManager<Rq, Rs, P>,

    firewall: FirewallConfiguration,
    permission_req_channel: mpsc::Sender<FirewallRequest<P>>,
    pending_rule_rqs: FuturesUnordered<PendingPeerRuleRequest>,
    pending_approval_rqs: FuturesUnordered<PendingApprovalRequest>,

    addresses: HashMap<PeerId, SmallVec<[Multiaddr; 6]>>,
    // TODO: Maintain a list of relays to use as backup
}

impl<Rq, Rs, P> NetBehaviour<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    pub fn new(
        config: NetBehaviourConfig,
        mdns: Mdns,
        relay: Relay,
        permission_req_channel: mpsc::Sender<FirewallRequest<P>>,
    ) -> Self {
        NetBehaviour {
            mdns,
            relay,
            supported_protocols: config.supported_protocols,
            request_timeout: config.request_timeout,
            connection_timeout: config.connection_timeout,
            next_request_id: RequestId::new(1),
            next_inbound_id: Arc::new(AtomicU64::new(1)),
            request_manager: RequestManager::new(),
            firewall: config.firewall,
            permission_req_channel,
            pending_rule_rqs: FuturesUnordered::default(),
            pending_approval_rqs: FuturesUnordered::default(),
            addresses: HashMap::new(),
        }
    }

    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let request_id = self.next_request_id();
        let (response_sender, response_receiver) = oneshot::channel();
        let receiver = ResponseReceiver {
            peer,
            request_id,
            receiver: response_receiver,
        };
        let request = Query {
            request,
            response_sender,
        };
        let approval_status = match self.firewall.get_out_rule_or_default(&peer) {
            None => {
                self.query_peer_rule(peer, RuleDirection::Outbound);
                ApprovalStatus::MissingRule
            }
            Some(Rule::Ask) => {
                self.query_rq_approval(
                    peer,
                    request_id,
                    request.request.to_permissioned(),
                    RequestDirection::Outbound,
                );
                ApprovalStatus::MissingApproval
            }
            Some(Rule::Permission(permission)) => {
                if permission.permits(&request.request.to_permissioned().permission()) {
                    ApprovalStatus::Approved
                } else {
                    ApprovalStatus::Rejected
                }
            }
        };
        self.request_manager
            .on_new_request(peer, request_id, request, approval_status, RequestDirection::Outbound);
        receiver
    }

    pub fn set_firewall_default(&mut self, direction: RuleDirection, default: Rule) {
        self.firewall.set_default(default, direction);
        let default_rules = self.firewall.get_default_rules().clone();
        self.request_manager.connected_peers().into_iter().for_each(|peer| {
            if let Some(rules) = self.firewall.get_rules(&peer) {
                if (!direction.is_inbound() || rules.inbound().is_some())
                    && (!direction.is_outbound() || rules.outbound().is_some())
                {
                    return;
                }
                let mut new_rules = default_rules.clone();
                if let Some(rule) = rules.inbound().cloned() {
                    new_rules.set_rule(Some(rule), RuleDirection::Inbound);
                }
                if let Some(rule) = rules.inbound().cloned() {
                    new_rules.set_rule(Some(rule), RuleDirection::Inbound);
                }
                self.handle_peer_rule(peer, new_rules, direction);
            } else {
                self.request_manager
                    .on_peer_rule(peer, default_rules.clone(), direction);
            }
        })
    }

    pub fn get_firewall_default(&self) -> &FirewallRules {
        self.firewall.get_default_rules()
    }

    pub fn remove_firewall_default(&mut self, direction: RuleDirection) {
        self.firewall.remove_default(direction);
        let default_rules = self.firewall.get_default_rules().clone();
        self.request_manager.connected_peers().into_iter().for_each(|peer| {
            let rules = self
                .firewall
                .get_rules(&peer)
                .cloned()
                .unwrap_or_else(|| default_rules.clone());
            self.handle_peer_rule(peer, rules, direction);
        })
    }

    pub fn get_peer_rules(&self, peer: &PeerId) -> Option<&FirewallRules> {
        self.firewall.get_rules(peer)
    }

    pub fn set_peer_rule(&mut self, peer: PeerId, direction: RuleDirection, rule: Rule) {
        self.firewall.set_rule(peer, rule, direction);
        self.update_peer_rule(peer, direction)
    }

    pub fn remove_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        if self.firewall.remove_rule(&peer, direction) {
            self.update_peer_rule(peer, direction);
        }
    }

    fn update_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        let mut new_rules = self.firewall.get_default_rules().clone();
        if let Some(peer_rules) = self.firewall.get_rules(&peer) {
            if let Some(inbound) = peer_rules.inbound() {
                new_rules.set_rule(Some(inbound.clone()), RuleDirection::Inbound);
            }
            if let Some(outbound) = peer_rules.outbound() {
                new_rules.set_rule(Some(outbound.clone()), RuleDirection::Outbound);
            }
        }
        self.handle_peer_rule(peer, new_rules, direction);
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

    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    fn handle_handler_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Rq, Rs>) {
        match event {
            HandlerOutEvent::ReceivedResponse(request_id) => {
                self.request_manager
                    .on_recv_res_for_outbound(peer, &connection, request_id, Ok(()));
            }
            HandlerOutEvent::RecvResponseOmission(request_id) => {
                let err = Err(RecvResponseErr::RecvResponseOmission);
                self.request_manager
                    .on_recv_res_for_outbound(peer, &connection, request_id, err);
            }
            HandlerOutEvent::ReceivedRequest { request_id, request } => {
                let approval_status = match self.firewall.get_in_rule_or_default(&peer) {
                    None => {
                        self.query_peer_rule(peer, RuleDirection::Inbound);
                        ApprovalStatus::MissingRule
                    }
                    Some(Rule::Ask) => {
                        self.query_rq_approval(
                            peer,
                            request_id,
                            request.request.to_permissioned(),
                            RequestDirection::Inbound,
                        );
                        ApprovalStatus::MissingApproval
                    }
                    Some(Rule::Permission(permission)) => {
                        if permission.permits(&request.request.to_permissioned().permission()) {
                            ApprovalStatus::Approved
                        } else {
                            ApprovalStatus::Rejected
                        }
                    }
                };
                self.request_manager.on_new_request(
                    peer,
                    request_id,
                    request,
                    approval_status,
                    RequestDirection::Inbound,
                )
            }
            HandlerOutEvent::OutboundTimeout(request_id) => {
                let err = Err(RecvResponseErr::Timeout);
                self.request_manager
                    .on_recv_res_for_outbound(peer, &connection, request_id, err);
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => {
                let err = Err(RecvResponseErr::UnsupportedProtocols);
                self.request_manager
                    .on_recv_res_for_outbound(peer, &connection, request_id, err);
            }
            HandlerOutEvent::InboundTimeout(request_id)
            | HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::SentResponse(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id) => {
                self.request_manager.on_recv_res_for_inbound(&connection, &request_id);
            }
        }
    }

    fn query_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        let reduced_direction = self
            .request_manager
            .pending_rule_requests(&peer)
            .map(|pending| direction.reduce(pending))
            .unwrap_or(Some(direction));
        let direction = unwrap_or_return!(reduced_direction);
        let (rule_sender, rule_receiver) = oneshot::channel();
        let firewall_req = FirewallRequest::<P>::PeerSpecificRule(Query {
            request: (peer, direction),
            response_sender: rule_sender,
        });
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());
        let future = send_firewall
            .and_then(move |()| rule_receiver.map_err(|_| ()))
            .map_ok_or_else(
                move |()| (peer, direction, None),
                move |rules| (peer, direction, Some(rules)),
            )
            .boxed();
        self.pending_rule_rqs.push(future);
        self.request_manager.add_pending_rule_requests(peer, direction);
    }

    fn query_rq_approval(&mut self, peer: PeerId, request_id: RequestId, request: P, direction: RequestDirection) {
        let (approval_sender, approval_receiver) = oneshot::channel();
        let firewall_req = FirewallRequest::RequestApproval(Query {
            request: (peer, direction, request),
            response_sender: approval_sender,
        });
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());
        let future = send_firewall
            .and_then(move |()| approval_receiver.map_err(|_| ()))
            .map_ok_or_else(move |()| (request_id, false), move |b| (request_id, b))
            .boxed();

        self.pending_approval_rqs.push(future);
    }

    async fn send_firewall(
        mut channel: mpsc::Sender<FirewallRequest<P>>,
        request: FirewallRequest<P>,
    ) -> Result<(), SendError> {
        poll_fn(|cx: &mut Context<'_>| channel.poll_ready(cx)).await?;
        channel.start_send(request)
    }

    fn handle_peer_rule(&mut self, peer: PeerId, rules: FirewallRules, direction: RuleDirection) {
        if let Some(ask_reqs) = self.request_manager.on_peer_rule(peer, rules, direction) {
            ask_reqs.into_iter().for_each(|(id, rq, dir)| {
                self.query_rq_approval(peer, id, rq, dir);
            })
        }
    }
}

impl<Rq, Rs, P> NetworkBehaviour for NetBehaviour<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    type ProtocolsHandler = IntoProtocolsHandlerSelect<ConnectionHandler<Rq, Rs>, MdnsRelayProtocolsHandler>;
    type OutEvent = BehaviourEvent<Rq, Rs>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        let handler = ConnectionHandler::new(
            self.supported_protocols.clone(),
            self.connection_timeout,
            self.request_timeout,
            self.next_inbound_id.clone(),
        );
        let mdns_handler = self.mdns.new_handler();
        let relay_handler = self.relay.new_handler();
        IntoProtocolsHandler::select(handler, IntoProtocolsHandler::select(mdns_handler, relay_handler))
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = self.addresses.get(peer).map(|v| v.to_vec()).unwrap_or_default();
        addresses.extend(self.mdns.addresses_of_peer(peer));
        addresses.extend(self.relay.addresses_of_peer(peer));
        addresses
    }

    fn inject_connected(&mut self, peer: &PeerId) {
        self.relay.inject_connected(peer);
        self.request_manager.on_peer_connected(*peer);
    }

    fn inject_disconnected(&mut self, peer: &PeerId) {
        self.relay.inject_disconnected(peer);
        self.mdns.inject_disconnected(peer);
        self.request_manager.on_peer_disconnected(*peer);
    }

    fn inject_connection_established(&mut self, peer: &PeerId, connection: &ConnectionId, endpoint: &ConnectedPoint) {
        let inbound_rule = self.firewall.get_in_rule_or_default(peer);
        let outbound_rule = self.firewall.get_out_rule_or_default(peer);
        let peer = *peer;
        let rules = FirewallRules::new(inbound_rule.cloned(), outbound_rule.cloned());
        self.request_manager.push_action(BehaviourAction::ReceivedPeerRules {
            peer,
            connection: Some(*connection),
            rules,
        });
        let has_no_rules = inbound_rule.is_none() && (outbound_rule.is_none());
        if let Some(dir) = has_no_rules
            .then(|| RuleDirection::Both)
            .or_else(|| inbound_rule.is_none().then(|| RuleDirection::Inbound))
            .or_else(|| outbound_rule.is_none().then(|| RuleDirection::Outbound))
        {
            self.query_peer_rule(peer, dir);
        }
        self.request_manager.on_connection_established(peer, *connection);
        self.relay.inject_connection_established(&peer, connection, endpoint);
    }

    fn inject_connection_closed(&mut self, peer: &PeerId, connection: &ConnectionId, endpoint: &ConnectedPoint) {
        // panic!();
        self.request_manager.on_connection_closed(*peer, connection);
        self.relay.inject_connection_closed(peer, connection, endpoint);
    }

    fn inject_address_change(&mut self, _: &PeerId, _: &ConnectionId, _old: &ConnectedPoint, _new: &ConnectedPoint) {}

    fn inject_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: <<Self::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    ) {
        match event {
            EitherOutput::First(ev) => self.handle_handler_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::First(ev)) => self.mdns.inject_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::Second(ev)) => self.relay.inject_event(peer, connection, ev),
        }
    }

    fn inject_addr_reach_failure(&mut self, _peer: Option<&PeerId>, _addr: &Multiaddr, _error: &dyn error::Error) {
        // TODO: attempt to reach via Relay.
    }

    fn inject_dial_failure(&mut self, peer: &PeerId) {
        self.request_manager.on_dial_failure(*peer);
        self.relay.inject_dial_failure(peer);
    }

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        self.mdns.inject_new_listen_addr(id, addr);
    }

    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl PollParameters) -> Poll<NetworkAction<Self>> {
        let _ = self.mdns.poll(cx, params);

        while let Poll::Ready(Some((peer, direction, rules))) = self.pending_rule_rqs.poll_next_unpin(cx) {
            if let Some(rules) = rules {
                self.firewall.set_rules(peer, rules.clone(), direction);
                self.update_peer_rule(peer, direction);
            } else {
                self.request_manager.on_no_peer_rule(peer, direction);
            }
        }

        while let Poll::Ready(Some((request_id, is_allowed))) = self.pending_approval_rqs.poll_next_unpin(cx) {
            self.request_manager.on_request_approval(request_id, is_allowed);
        }

        if let Poll::Ready(action) = self.relay.poll(cx, params) {
            match action {
                NetworkBehaviourAction::DialPeer { peer_id, condition } => {
                    return Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition })
                }
                NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id,
                        handler,
                        event: EitherOutput::Second(EitherOutput::Second(event)),
                    })
                }
                _ => {}
            }
        }
        if let Some(event) = self.request_manager.take_next_action() {
            let action = match event {
                BehaviourAction::InboundReady {
                    request_id,
                    peer,
                    request,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceiveRequest {
                    peer,
                    request_id,
                    request,
                }),
                BehaviourAction::OutboundReady {
                    request_id,
                    peer,
                    connection,
                    request,
                } => {
                    let event = HandlerInEvent::SendRequest { request_id, request };
                    NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::One(connection),
                        event: EitherOutput::First(event),
                    }
                }
                BehaviourAction::OutboundRejected { peer, request_id } => {
                    NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceiveResponse {
                        peer,
                        request_id,
                        result: Err(RecvResponseErr::NotPermitted),
                    })
                }

                BehaviourAction::RequireDialAttempt(peer) => NetworkBehaviourAction::DialPeer {
                    peer_id: peer,
                    condition: DialPeerCondition::Disconnected,
                },
                BehaviourAction::ReceivedResponse {
                    peer,
                    request_id,
                    result,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result,
                }),
                BehaviourAction::ReceivedPeerRules {
                    peer,
                    connection,
                    rules,
                } => {
                    let handler = connection.map(NotifyHandler::One).unwrap_or(NotifyHandler::Any);
                    let event = HandlerInEvent::SetFirewallRules(rules);
                    NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer,
                        handler,
                        event: EitherOutput::First(event),
                    }
                }
            };
            return Poll::Ready(action);
        }
        Poll::Pending
    }
}

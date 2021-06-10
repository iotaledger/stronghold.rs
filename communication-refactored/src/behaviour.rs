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

#[doc(hidden)]
mod addresses;
pub mod firewall;
#[doc(hidden)]
mod handler;
#[doc(hidden)]
mod request_manager;
use crate::{
    unwrap_or_return, InboundFailure, OutboundFailure, ReceiveRequest, RequestDirection, RequestId, RequestMessage,
    ResponseReceiver, RqRsMessage,
};
pub use addresses::assemble_relayed_addr;
use addresses::AddressInfo;
use firewall::{
    FirewallConfiguration, FirewallRequest, FirewallRules, PeerRuleQuery, RequestApprovalQuery, Rule, RuleDirection,
    ToPermissionVariants, VariantPermission,
};
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
use handler::{ConnectionHandler, HandlerInEvent, HandlerOutEvent};
use libp2p::{
    core::{
        connection::{ConnectionId, ListenerId},
        either::EitherOutput,
        ConnectedPoint, Multiaddr, PeerId,
    },
    relay::Relay,
    swarm::{
        DialPeerCondition, IntoProtocolsHandler, IntoProtocolsHandlerSelect, NetworkBehaviour, NetworkBehaviourAction,
        NotifyHandler, PollParameters, ProtocolsHandler,
    },
};

#[cfg(feature = "mdns")]
use libp2p::mdns::Mdns;
use request_manager::{ApprovalStatus, BehaviourAction, RequestManager};
use smallvec::{smallvec, SmallVec};
use std::{
    error,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

type NetworkAction<Proto> = NetworkBehaviourAction<
    <<<Proto as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <Proto as NetworkBehaviour>::OutEvent,
>;

#[cfg(feature = "mdns")]
type SecondProtocolsHandler = IntoProtocolsHandlerSelect<
    <Mdns as NetworkBehaviour>::ProtocolsHandler,
    <Relay as NetworkBehaviour>::ProtocolsHandler,
>;
#[cfg(not(feature = "mdns"))]
type SecondProtocolsHandler = <Relay as NetworkBehaviour>::ProtocolsHandler;

pub type PendingPeerRuleRequest = BoxFuture<'static, (PeerId, RuleDirection, Option<FirewallRules>)>;
pub type PendingApprovalRequest = BoxFuture<'static, (RequestId, bool)>;

const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

#[derive(Debug)]
pub enum BehaviourEvent<Rq, Rs> {
    Request(ReceiveRequest<Rq, Rs>),
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    OutboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: OutboundFailure,
    },
}

impl<Rq, Rs> Unpin for BehaviourEvent<Rq, Rs> {}

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
    addresses: AddressInfo,
    firewall: FirewallConfiguration,

    permission_req_channel: mpsc::Sender<FirewallRequest<P>>,
    pending_rule_rqs: FuturesUnordered<PendingPeerRuleRequest>,
    pending_approval_rqs: FuturesUnordered<PendingApprovalRequest>,
}

impl<Rq, Rs, P> NetBehaviour<Rq, Rs, P>
where
    Rq: RqRsMessage + ToPermissionVariants<P>,
    Rs: RqRsMessage,
    P: VariantPermission,
{
    pub fn new(
        config: NetBehaviourConfig,
        #[cfg(feature = "mdns")] mdns: Mdns,
        relay: Relay,
        permission_req_channel: mpsc::Sender<FirewallRequest<P>>,
    ) -> Self {
        NetBehaviour {
            #[cfg(feature = "mdns")]
            mdns,
            relay,
            supported_protocols: config.supported_protocols,
            request_timeout: config.request_timeout,
            connection_timeout: config.connection_timeout,
            next_request_id: RequestId::new(1),
            next_inbound_id: Arc::new(AtomicU64::new(1)),
            request_manager: RequestManager::new(),
            addresses: AddressInfo::new(),
            firewall: config.firewall,
            permission_req_channel,
            pending_rule_rqs: FuturesUnordered::default(),
            pending_approval_rqs: FuturesUnordered::default(),
        }
    }

    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let request_id = self.next_request_id();
        let (response_tx, response_rx) = oneshot::channel();
        let receiver = ResponseReceiver {
            peer,
            request_id,
            response_rx,
        };
        let query = RequestMessage {
            data: request,
            response_tx,
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
                    query.data.to_permissioned(),
                    RequestDirection::Outbound,
                );
                ApprovalStatus::MissingApproval
            }
            Some(Rule::Permission(permission)) => {
                if permission.permits(&query.data.to_permissioned().permission()) {
                    ApprovalStatus::Approved
                } else {
                    ApprovalStatus::Rejected
                }
            }
        };
        self.request_manager
            .on_new_request(peer, request_id, query, approval_status, RequestDirection::Outbound);
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
                if let Some(rule) = rules.outbound().cloned() {
                    new_rules.set_rule(Some(rule), RuleDirection::Outbound);
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

    pub fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        self.addresses.add_addrs(peer, address);
    }

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        self.addresses.remove_address(peer, address);
    }

    pub fn get_relay_addr(&self, relay: &PeerId) -> Option<Multiaddr> {
        self.addresses.get_relay_addr(relay)
    }

    pub fn add_dialing_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        self.addresses.add_relay(peer, address)
    }

    pub fn remove_dialing_relay(&mut self, peer: &PeerId) {
        self.addresses.remove_relay(peer);
    }

    pub fn set_not_use_relay(&mut self, peer: PeerId) {
        self.addresses.set_no_relay(peer);
    }

    pub fn set_use_relay(&mut self, peer: PeerId, relay: PeerId) -> Option<Multiaddr> {
        self.addresses.set_relay(peer, relay)
    }

    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    fn handle_handler_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Rq, Rs>) {
        match event {
            HandlerOutEvent::ReceivedResponse(request_id) => {
                self.request_manager
                    .on_res_for_outbound(peer, &connection, request_id, Ok(()));
            }
            HandlerOutEvent::RecvResponseOmission(request_id) => {
                let err = Err(OutboundFailure::RecvResponseOmission);
                self.request_manager
                    .on_res_for_outbound(peer, &connection, request_id, err);
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
                            request.data.to_permissioned(),
                            RequestDirection::Inbound,
                        );
                        ApprovalStatus::MissingApproval
                    }
                    Some(Rule::Permission(permission)) => {
                        if permission.permits(&request.data.to_permissioned().permission()) {
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
                let err = Err(OutboundFailure::Timeout);
                self.request_manager
                    .on_res_for_outbound(peer, &connection, request_id, err);
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => {
                let err = Err(OutboundFailure::UnsupportedProtocols);
                self.request_manager
                    .on_res_for_outbound(peer, &connection, request_id, err);
            }
            HandlerOutEvent::InboundTimeout(request_id) => {
                let err = InboundFailure::Timeout;
                self.request_manager
                    .on_res_for_inbound(peer, &connection, request_id, Err(err));
            }
            HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id)
            | HandlerOutEvent::SentResponse(request_id) => {
                self.request_manager
                    .on_res_for_inbound(peer, &connection, request_id, Ok(()));
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
        let (rule_tx, rule_rx) = oneshot::channel();
        let firewall_req = FirewallRequest::<P>::PeerSpecificRule(PeerRuleQuery {
            data: (peer, direction),
            response_tx: rule_tx,
        });
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());
        let future = send_firewall
            .and_then(move |()| rule_rx.map_err(|_| ()))
            .map_ok_or_else(
                move |()| (peer, direction, None),
                move |rules| (peer, direction, Some(rules)),
            )
            .boxed();
        self.pending_rule_rqs.push(future);
        self.request_manager.add_pending_rule_requests(peer, direction);
    }

    fn query_rq_approval(&mut self, peer: PeerId, request_id: RequestId, rq_type: P, direction: RequestDirection) {
        let (approval_tx, approval_rx) = oneshot::channel();
        let firewall_req = FirewallRequest::RequestApproval(RequestApprovalQuery {
            data: (peer, direction, rq_type),
            response_tx: approval_tx,
        });
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());
        let future = send_firewall
            .and_then(move |()| approval_rx.map_err(|_| ()))
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
    type ProtocolsHandler = IntoProtocolsHandlerSelect<ConnectionHandler<Rq, Rs>, SecondProtocolsHandler>;
    type OutEvent = BehaviourEvent<Rq, Rs>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        let handler = ConnectionHandler::new(
            self.supported_protocols.clone(),
            self.connection_timeout,
            self.request_timeout,
            self.next_inbound_id.clone(),
        );
        #[cfg(feature = "mdns")]
        let mdns_handler = self.mdns.new_handler();
        let relay_handler = self.relay.new_handler();

        #[cfg(feature = "mdns")]
        let protocols_handler =
            IntoProtocolsHandler::select(handler, IntoProtocolsHandler::select(mdns_handler, relay_handler));

        #[cfg(not(feature = "mdns"))]
        let protocols_handler = IntoProtocolsHandler::select(handler, relay_handler);

        protocols_handler
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = self.addresses.get_addrs(peer);
        #[cfg(feature = "mdns")]
        addresses.extend(self.mdns.addresses_of_peer(peer));
        addresses.extend(self.relay.addresses_of_peer(peer));
        addresses
    }

    fn inject_connected(&mut self, peer: &PeerId) {
        self.relay.inject_connected(peer);
        #[cfg(feature = "mdns")]
        self.mdns.inject_connected(peer);
        self.request_manager.on_peer_connected(*peer);
    }

    fn inject_disconnected(&mut self, peer: &PeerId) {
        self.relay.inject_disconnected(peer);
        #[cfg(feature = "mdns")]
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
        self.request_manager.on_connection_established(peer, *connection);
        self.addresses
            .on_connection_established(peer, endpoint.get_remote_address().clone());
        self.relay.inject_connection_established(&peer, connection, endpoint);
        #[cfg(feature = "mdns")]
        self.mdns.inject_connection_established(&peer, connection, endpoint);
    }

    fn inject_connection_closed(&mut self, peer: &PeerId, connection: &ConnectionId, endpoint: &ConnectedPoint) {
        self.request_manager.on_connection_closed(*peer, connection);
        self.addresses
            .on_connection_closed(*peer, endpoint.get_remote_address());
        self.relay.inject_connection_closed(peer, connection, endpoint);
        #[cfg(feature = "mdns")]
        self.mdns.inject_connection_closed(peer, connection, endpoint);
    }

    fn inject_address_change(
        &mut self,
        peer: &PeerId,
        connection: &ConnectionId,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        self.relay.inject_address_change(peer, connection, old, new);
        #[cfg(feature = "mdns")]
        self.mdns.inject_address_change(peer, connection, old, new);
    }

    fn inject_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: <<Self::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    ) {
        #[cfg(feature = "mdns")]
        match event {
            EitherOutput::First(ev) => self.handle_handler_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::First(ev)) => self.mdns.inject_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::Second(ev)) => self.relay.inject_event(peer, connection, ev),
        }
        #[cfg(not(feature = "mdns"))]
        match event {
            EitherOutput::First(ev) => self.handle_handler_event(peer, connection, ev),
            EitherOutput::Second(ev) => self.relay.inject_event(peer, connection, ev),
        }
    }

    fn inject_addr_reach_failure(&mut self, peer: Option<&PeerId>, addr: &Multiaddr, error: &dyn error::Error) {
        self.relay.inject_addr_reach_failure(peer, addr, error);
        #[cfg(feature = "mdns")]
        self.mdns.inject_addr_reach_failure(peer, addr, error);
        if let Some(peer) = peer {
            self.addresses.remove_address(peer, addr);
        }
    }

    fn inject_dial_failure(&mut self, peer: &PeerId) {
        self.request_manager.on_dial_failure(*peer);
        self.relay.inject_dial_failure(peer);
        #[cfg(feature = "mdns")]
        self.mdns.inject_dial_failure(peer);
    }

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        #[cfg(feature = "mdns")]
        self.mdns.inject_new_listen_addr(id, addr);
        self.relay.inject_new_listen_addr(id, addr);
    }

    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl PollParameters) -> Poll<NetworkAction<Self>> {
        #[cfg(feature = "mdns")]
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
                    #[cfg(feature = "mdns")]
                    let event = EitherOutput::Second(EitherOutput::Second(event));
                    #[cfg(not(feature = "mdns"))]
                    let event = EitherOutput::Second(event);
                    return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    });
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
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::Request(ReceiveRequest {
                    peer,
                    request_id,
                    request,
                })),
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
                BehaviourAction::OutboundFailure {
                    peer,
                    request_id,
                    reason,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::OutboundFailure {
                    peer,
                    request_id,
                    failure: reason,
                }),
                BehaviourAction::InboundFailure {
                    peer,
                    request_id,
                    reason,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::InboundFailure {
                    peer,
                    request_id,
                    failure: reason,
                }),
                BehaviourAction::RequireDialAttempt(peer) => NetworkBehaviourAction::DialPeer {
                    peer_id: peer,
                    condition: DialPeerCondition::Disconnected,
                },
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::firewall::{PermissionValue, RequestPermissions, Rule, RuleDirection, VariantPermission};
    use futures::{channel::mpsc, executor::LocalPool, future::FutureObj, prelude::*, select, task::Spawn};
    #[cfg(feature = "mdns")]
    use libp2p::mdns::{Mdns, MdnsConfig};
    use libp2p::{
        core::{identity, transport::Transport, upgrade, Multiaddr, PeerId},
        noise::{Keypair, NoiseConfig, X25519Spec},
        relay::{new_transport_and_behaviour, RelayConfig},
        swarm::{Swarm, SwarmEvent},
        tcp::TcpConfig,
        yamux::YamuxConfig,
    };
    use serde::{Deserialize, Serialize};

    // Exercises a simple ping protocol.
    #[test]
    fn ping_protocol() {
        let mut pool = LocalPool::new();
        let spawner = pool.spawner();

        let ping = Ping("ping".to_string().into_bytes());
        let pong = Pong("pong".to_string().into_bytes());

        let (peer1_id, mut swarm1) = init_swarm(&mut pool);
        let (peer2_id, mut swarm2) = init_swarm(&mut pool);

        let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        let expected_ping = ping.clone();

        let peer1_future = async move {
            loop {
                match swarm1.next_event().await {
                    SwarmEvent::NewListenAddr(addr) => tx.send(addr).await.unwrap(),
                    SwarmEvent::Behaviour(BehaviourEvent::Request(ReceiveRequest {
                        peer,
                        request: RequestMessage { data, response_tx, .. },
                        ..
                    })) => {
                        assert_eq!(&data, &expected_ping);
                        assert_eq!(&peer, &peer2_id);
                        response_tx.send(pong.clone()).unwrap();
                    }
                    SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                    _ => {}
                }
            }
        };

        let num_pings = 100;

        let peer2_future = async move {
            let mut count = 0u8;
            let addr = rx.next().await.unwrap();
            swarm2.behaviour_mut().add_address(peer1_id, addr.clone());
            let mut response_recv = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

            loop {
                select! {
                    _ = swarm2.next().fuse() => panic!(),
                    _ = response_recv.response_rx.fuse() => {
                        count += 1;
                        if count >= num_pings {
                            return;
                        } else {
                            response_recv = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());
                        }
                    }
                }
            }
        };

        spawner.spawn_obj(FutureObj::new(Box::pin(peer1_future))).unwrap();
        pool.run_until(peer2_future);
    }

    #[test]
    fn emits_inbound_connection_closed_failure() {
        let mut pool = LocalPool::new();

        let ping = Ping("ping".to_string().into_bytes());
        let pong = Pong("pong".to_string().into_bytes());

        let (peer1_id, mut swarm1) = init_swarm(&mut pool);
        let (peer2_id, mut swarm2) = init_swarm(&mut pool);

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        pool.run_until(async move {
            while swarm1.next().now_or_never().is_some() {}
            let addr1 = Swarm::listeners(&swarm1).next().unwrap();

            swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
            swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

            // Wait for swarm 1 to receive request by swarm 2.
            let response_tx = loop {
                futures::select!(
                    event = swarm1.next().fuse() => match event {
                        BehaviourEvent::Request(ReceiveRequest {
                            peer,
                            request: RequestMessage { data, response_tx, .. },
                            ..
                        }) => {
                            assert_eq!(&data, &ping);
                            assert_eq!(&peer, &peer2_id);
                            break response_tx
                        },
                        e => panic!("Peer1: Unexpected event: {:?}", e)
                    },
                    event = swarm2.next().fuse() => panic!("Peer2: Unexpected event: {:?}", event),
                )
            };

            // Drop swarm 2 in order for the connection between swarm 1 and 2 to close.
            drop(swarm2);

            match swarm1.next_event().await {
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == peer2_id => {
                    assert!(response_tx.send(pong).is_err());
                }
                e => panic!("Peer1: Unexpected event: {:?}", e),
            }
        });
    }

    /// We expect the substream to be properly closed when response channel is dropped.
    /// Since the ping protocol used here expects a response, the sender considers this
    /// early close as a protocol violation which results in the connection being closed.
    /// If the substream were not properly closed when dropped, the sender would instead
    /// run into a timeout waiting for the response.
    #[test]
    fn emits_inbound_connection_closed_if_channel_is_dropped() {
        let mut pool = LocalPool::new();
        let ping = Ping("ping".to_string().into_bytes());

        let (peer1_id, mut swarm1) = init_swarm(&mut pool);
        let (peer2_id, mut swarm2) = init_swarm(&mut pool);

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        pool.run_until(async move {
            while swarm1.next().now_or_never().is_some() {}
            let addr1 = Swarm::listeners(&swarm1).next().unwrap();

            swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
            let mut response_rx = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

            // Wait for swarm 1 to receive request by swarm 2.
            let event = loop {
                futures::select!(
                    event = swarm1.next().fuse() => match event {
                        BehaviourEvent::Request(ReceiveRequest {
                            peer,
                            request: RequestMessage { data, response_tx, .. },
                            ..
                        }) => {
                            assert_eq!(&data, &ping);
                            assert_eq!(&peer, &peer2_id);
                            drop(response_tx);
                            continue;
                        },
                        e => panic!("Peer1: Unexpected event: {:?}", e)
                    },
                    event = swarm2.next().fuse() => break event,
                )
            };

            match event {
                BehaviourEvent::OutboundFailure {
                    peer,
                    request_id,
                    failure: OutboundFailure::ConnectionClosed,
                } => {
                    assert_eq!(peer, peer1_id);
                    assert_eq!(request_id, response_rx.request_id);
                    assert!(response_rx.response_rx.try_recv().is_err())
                }
                e => panic!("unexpected event from peer 2: {:?}", e),
            };
        });
    }

    fn init_swarm(_pool: &mut LocalPool) -> (PeerId, Swarm<NetBehaviour<Ping, Pong, Ping>>) {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer = id_keys.public().into_peer_id();
        let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
        let (relay_transport, relay_behaviour) =
            new_transport_and_behaviour(RelayConfig::default(), TcpConfig::new().nodelay(true));
        let transport = relay_transport
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed();

        let mut cfg = NetBehaviourConfig::default();
        cfg.firewall.set_default(Rule::allow_all(), RuleDirection::Both);
        #[cfg(feature = "mdns")]
        let mdns = _pool
            .run_until(Mdns::new(MdnsConfig::default()))
            .expect("Failed to create mdns behaviour.");
        let (dummy_tx, _) = mpsc::channel(1);
        let behaviour = NetBehaviour::new(
            cfg,
            #[cfg(feature = "mdns")]
            mdns,
            relay_behaviour,
            dummy_tx,
        );
        (peer, Swarm::new(transport, behaviour, peer))
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
    struct Ping(Vec<u8>);
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
    struct Pong(Vec<u8>);
}

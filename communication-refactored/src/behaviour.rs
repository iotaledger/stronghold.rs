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
use handler::{ConnectionHandler, HandlerInEvent, HandlerOutEvent, ProtocolSupport};
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

    /// Send a new request to a remote peer.
    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> ResponseReceiver<Rs> {
        let request_id = self.next_request_id();
        let (response_tx, response_rx) = oneshot::channel();
        let receiver = ResponseReceiver {
            peer,
            request_id,
            response_rx,
        };
        let request = RequestMessage {
            data: request,
            response_tx,
        };
        self.handle_new_request(peer, request_id, request, RequestDirection::Outbound);
        receiver
    }

    /// Get the current default rules for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub fn get_firewall_default(&self) -> &FirewallRules {
        self.firewall.get_default_rules()
    }

    /// Set the default configuration for the firewall.
    /// The default rules are used for peers that do not have any explicit rules.
    pub fn set_firewall_default(&mut self, direction: RuleDirection, default: Rule) {
        self.firewall.set_default(Some(default), direction);
        self.request_manager.connected_peers().into_iter().for_each(|peer| {
            if let Some(rules) = self.firewall.get_rules(&peer) {
                if (rules.inbound().is_some() || !direction.is_inbound())
                    && (rules.outbound().is_some() || !direction.is_outbound())
                {
                    return;
                }
            }
            self.handle_updated_peer_rule(peer, direction);
        })
    }

    /// Remove a default firewall rule.
    /// If there is no default rule and no peer-specific rule, a [`FirewallRequest::PeerSpecificRule`]
    /// request will be sent through the firewall channel
    pub fn remove_firewall_default(&mut self, direction: RuleDirection) {
        let old_rules = self.firewall.get_default_rules();
        let is_change = (old_rules.inbound().is_some() && direction.is_inbound())
            || (old_rules.inbound().is_some() && direction.is_inbound());
        self.firewall.set_default(None, direction);
        if is_change {
            self.request_manager.connected_peers().iter().for_each(|peer| {
                // Check if peer is affected
                if let Some(rules) = self.firewall.get_rules(&peer) {
                    if (rules.inbound().is_some() || !direction.is_inbound())
                        && (rules.outbound().is_some() || !direction.is_outbound())
                    {
                        // Skip peer if they have explicit rules for the direction and hence are not affected
                        return;
                    }
                }
                self.handle_updated_peer_rule(*peer, direction);
            })
        }
    }

    /// Get the explicit rules for a peer, if there are any.
    pub fn get_peer_rules(&self, peer: &PeerId) -> Option<&FirewallRules> {
        self.firewall.get_rules(peer)
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub fn set_peer_rule(&mut self, peer: PeerId, direction: RuleDirection, rule: Rule) {
        self.firewall.set_rule(peer, Some(rule), direction);
        self.handle_updated_peer_rule(peer, direction);
    }

    /// Remove a peer specific rule, which will result in using the firewall default rules.
    pub fn remove_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        self.firewall.set_rule(peer, None, direction);
        self.handle_updated_peer_rule(peer, direction);
    }

    /// Add an address for the remote peer.
    pub fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        self.addresses.add_addrs(peer, address);
    }

    /// Remove an address from the known addresses of a remote peer.
    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        self.addresses.remove_address(peer, address);
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub fn add_dialing_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        self.addresses.add_relay(peer, address)
    }

    /// Remove a relay from the list of dialing relays.
    pub fn remove_dialing_relay(&mut self, peer: &PeerId) {
        self.addresses.remove_relay(peer);
    }

    /// Configure whether it should be attempted to reach the remote via known relays, if it can not be reached via
    /// known addresses.
    pub fn set_relay_fallback(&mut self, peer: PeerId, use_relay_fallback: bool) {
        self.addresses.set_relay_fallback(peer, use_relay_fallback);
    }

    /// Dial the target via the specified relay.
    /// The `is_exclusive` specifies whether other known relays should be used if using the set relay is not successful.
    ///
    /// Returns the relayed address of the local peer (`<relay-addr>/<relay-id>/p2p-circuit/<local-id>),
    /// if an address for the relay is known.
    pub fn use_specific_relay(&mut self, target: PeerId, relay: PeerId, is_exclusive: bool) -> Option<Multiaddr> {
        self.addresses.use_relay(target, relay, is_exclusive)
    }

    /// [`RequestId`] for the next outbound request.
    fn next_request_id(&mut self) -> RequestId {
        *self.next_request_id.inc()
    }

    // Handle a new inbound/ outbound request
    fn handle_new_request(
        &mut self,
        peer: PeerId,
        request_id: RequestId,
        request: RequestMessage<Rq, Rs>,
        direction: RequestDirection,
    ) {
        // Check the firewall rules for the target peer and direction.
        let rules = self.firewall.get_effective_rules(&peer);
        let rule = match direction {
            RequestDirection::Inbound => rules.inbound(),
            RequestDirection::Outbound => rules.outbound(),
        };
        let approval_status = match rule {
            None => {
                let rule_direction = match direction {
                    RequestDirection::Inbound => RuleDirection::Inbound,
                    RequestDirection::Outbound => RuleDirection::Outbound,
                };
                // Query for a new peer specific rule.
                self.query_peer_rule(peer, rule_direction);
                ApprovalStatus::MissingRule
            }
            Some(Rule::Ask) => {
                // Query for individual approval for the requests.
                self.query_rq_approval(peer, request_id, request.data.to_permissioned(), direction.clone());
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
        self.request_manager
            .on_new_request(peer, request_id, request, approval_status, direction);
    }

    // Handle new [`HandlerOutEvent`] emitted by the [`ConnectionHandler`].
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
                self.handle_new_request(peer, request_id, request, RequestDirection::Inbound);
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

    // Query for a new peer-specific firewall rule.
    // Since is necessary if there is neither an existing default, nor a peer specific rule.
    fn query_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        // Only query for the direction for which there is no pending request already.
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
        // Send request through the firewall channel, add to pending rule requests.
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

    // Query for individual approval of a requests.
    // This is necessary if the firewall is configured with [`Rule::Ask`].
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

    // Send a request through the firewall channel.
    async fn send_firewall(
        mut channel: mpsc::Sender<FirewallRequest<P>>,
        request: FirewallRequest<P>,
    ) -> Result<(), SendError> {
        poll_fn(|cx: &mut Context<'_>| channel.poll_ready(cx)).await?;
        channel.start_send(request)
    }

    // Handle a changed firewall rule for a peer.
    fn handle_updated_peer_rule(&mut self, peer: PeerId, direction: RuleDirection) {
        // Set protocol support for the active handlers according to the new rules.
        let rules = self.firewall.get_effective_rules(&peer);
        let set_support = ProtocolSupport::from_rules(rules.inbound(), rules.outbound());
        self.request_manager.set_protocol_support(peer, None, set_support);
        // Query for individual request approval due to [`Rule::Ask`].
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
        // Use the default firewall rules as protocol support.
        // As soon as the connection is established, this will potentially be updated with the peer-specific rules.
        let default_rules = self.firewall.get_default_rules();
        let default_support = ProtocolSupport::from_rules(default_rules.inbound(), default_rules.outbound());
        let handler = ConnectionHandler::new(
            self.supported_protocols.clone(),
            default_support,
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
        // Overwrite the default protocol support if the peer has explicit rules.
        if self.firewall.get_rules(peer).is_some() {
            let default_rules = self.firewall.get_default_rules();
            let default_support = ProtocolSupport::from_rules(default_rules.inbound(), default_rules.outbound());
            let peer_rules = self.firewall.get_effective_rules(peer);
            let support = ProtocolSupport::from_rules(peer_rules.inbound(), peer_rules.outbound());
            if default_support != support {
                // Overwrite default protocol support with the protocol support derived from the peer-specific rules.
                self.request_manager
                    .set_protocol_support(*peer, Some(*connection), support);
            }
        }
        self.request_manager.on_connection_established(*peer, *connection);
        self.addresses
            .prioritize_addr(*peer, endpoint.get_remote_address().clone());
        self.relay.inject_connection_established(peer, connection, endpoint);
        #[cfg(feature = "mdns")]
        self.mdns.inject_connection_established(peer, connection, endpoint);
    }

    fn inject_connection_closed(&mut self, peer: &PeerId, connection: &ConnectionId, endpoint: &ConnectedPoint) {
        self.request_manager.on_connection_closed(*peer, connection);
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
            self.addresses.deprioritize_addr(*peer, addr.clone());
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
        // Drive mdns.
        #[cfg(feature = "mdns")]
        let _ = self.mdns.poll(cx, params);

        // Update firewall rules if a peer specific rule was return after a `FirewallRequest::PeerSpecificRule` query.
        while let Poll::Ready(Some((peer, direction, rules))) = self.pending_rule_rqs.poll_next_unpin(cx) {
            if let Some(rules) = rules {
                if direction.is_inbound() {
                    self.firewall
                        .set_rule(peer, rules.inbound().cloned(), RuleDirection::Inbound)
                }
                if direction.is_outbound() {
                    self.firewall
                        .set_rule(peer, rules.outbound().cloned(), RuleDirection::Outbound)
                }
                self.handle_updated_peer_rule(peer, direction);
            } else {
                self.request_manager.on_no_peer_rule(peer, direction);
            }
        }

        // Handle individual approvals fro requests that were returned after a `FirewallRequest::RequestApproval` query.
        while let Poll::Ready(Some((request_id, is_allowed))) = self.pending_approval_rqs.poll_next_unpin(cx) {
            self.request_manager.on_request_approval(request_id, is_allowed);
        }

        // Handle events from the relay protocol.
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

        // Emit events for pending requests and required dial attempts.
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
                BehaviourAction::SetProtocolSupport {
                    peer,
                    connection,
                    support,
                } => {
                    let event = HandlerInEvent::SetProtocolSupport(support);
                    NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::One(connection),
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
                futures::select_biased!(
                    event = swarm2.next().fuse() => panic!("Peer2: Unexpected event: {:?}", event),
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
                futures::select_biased!(
                    event = swarm2.next().fuse() => break event,
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
        cfg.firewall.set_default(Some(Rule::allow_all()), RuleDirection::Both);
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

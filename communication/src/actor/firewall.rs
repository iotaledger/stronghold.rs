// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;
use libp2p::PeerId;
use riker::actors::*;
use std::collections::HashMap;

/// The direction of a [`CommunicationRequest::RequestMsg`] that firewall receives.
#[derive(Debug, Clone)]
pub enum RequestDirection {
    /// Incoming request from a remote peer to the local system.
    In,
    /// Outgoing request from the local system to a remote peer.
    Out,
}

/// Request to the firewall to obtain approval for a request from/ to a remote peer.
/// If no [`FirewallResponse::Accept`] is returned, the request will be rejected.
#[derive(Debug, Clone)]
pub struct FirewallRequest<Req> {
    request: Req,
    remote: PeerId,
    direction: RequestDirection,
}

impl<Req> FirewallRequest<Req> {
    pub fn new(request: Req, remote: PeerId, direction: RequestDirection) -> Self {
        FirewallRequest {
            request,
            remote,
            direction,
        }
    }
}

/// The expected response that should be send back from the firewall actor for a [`FirewallRequest`].
#[derive(Debug, Clone, Copy)]
pub enum FirewallResponse {
    Accept,
    Reject,
}

// Open firewall that approves all requests and connections
#[derive(Debug, Clone)]
pub struct OpenFirewall<Req: Message> {
    marker: PhantomData<Req>,
}

impl<Req: Message> ActorFactory for OpenFirewall<Req> {
    fn create() -> Self {
        OpenFirewall { marker: PhantomData }
    }
}

impl<Req: Message> Actor for OpenFirewall<Req> {
    type Msg = FirewallRequest<Req>;

    fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
        // Allows all  messages.
        sender.unwrap().try_tell(FirewallResponse::Accept, None).unwrap()
    }
}

/// Permission for a specific peer.
#[derive(Debug, Clone)]
pub struct FirewallRule {
    peer_id: PeerId,
    permission: FirewallResponse,
}

impl FirewallRule {
    pub fn new(peer_id: PeerId, permission: FirewallResponse) -> Self {
        FirewallRule { peer_id, permission }
    }
}

// Wrapped message type of the RestrictConnectionFirewall actor
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum RestrictConnectionFirewallMsg<Req: Message> {
    // Query from CommunicationActor for approval of a connection or request message.
    Request(FirewallRequest<Req>),
    // Set connection permission for a specific peer.
    Rule(FirewallRule),
}

impl<Req: Message> From<FirewallRequest<Req>> for RestrictConnectionFirewallMsg<Req> {
    fn from(ty: FirewallRequest<Req>) -> Self {
        RestrictConnectionFirewallMsg::Request(ty)
    }
}

impl<Req: Message> From<FirewallRule> for RestrictConnectionFirewallMsg<Req> {
    fn from(ty: FirewallRule) -> Self {
        RestrictConnectionFirewallMsg::Rule(ty)
    }
}

// Restricted Firewall that only allows request for certain peers.
#[derive(Debug, Clone)]
pub struct RestrictConnectionFirewall<Req: Message> {
    default: FirewallResponse,
    rules: HashMap<PeerId, FirewallResponse>,
    marker: PhantomData<Req>,
}

impl<Req: Message> ActorFactoryArgs<FirewallResponse> for RestrictConnectionFirewall<Req> {
    // Create a [`CommunicationActor`] that spwans a task to poll from the swarm.
    // The provided keypair is used to authenticate the swarm communication.
    fn create_args(default: FirewallResponse) -> Self {
        Self {
            default,
            rules: HashMap::new(),
            marker: PhantomData,
        }
    }
}

impl<Req: Message> Actor for RestrictConnectionFirewall<Req> {
    type Msg = RestrictConnectionFirewallMsg<Req>;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            RestrictConnectionFirewallMsg::Request(req) => {
                <RestrictConnectionFirewall<Req> as Receive<FirewallRequest<Req>>>::receive(self, ctx, req, sender)
            }
            RestrictConnectionFirewallMsg::Rule(rule) => {
                <RestrictConnectionFirewall<Req> as Receive<FirewallRule>>::receive(self, ctx, rule, sender)
            }
        }
    }
}

impl<Req: Message> Receive<FirewallRule> for RestrictConnectionFirewall<Req> {
    type Msg = RestrictConnectionFirewallMsg<Req>;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: FirewallRule, _sender: Sender) {
        self.rules.insert(msg.peer_id, msg.permission);
    }
}

impl<Req: Message> Receive<FirewallRequest<Req>> for RestrictConnectionFirewall<Req> {
    type Msg = RestrictConnectionFirewallMsg<Req>;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: FirewallRequest<Req>, sender: Sender) {
        let rule = *self.rules.get(&msg.remote).unwrap_or(&self.default);
        sender.unwrap().try_tell(rule, None).unwrap()
    }
}

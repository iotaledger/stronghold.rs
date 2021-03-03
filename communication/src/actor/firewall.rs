// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;
use libp2p::PeerId;
use riker::actors::*;
use std::collections::HashMap;

pub type PermissionSum = u32;

pub trait VariantPermission {
    fn variant_permission_value(&self) -> PermissionSum;
    fn is_permitted(&self, permission: PermissionSum) -> bool;
}

pub trait ToPermissionVariants<P: VariantPermission> {
    fn to_permission_variants(&self) -> P;
}

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
pub struct FirewallRequest<P>
where
    P: Message + VariantPermission,
{
    variant: P,
    remote: PeerId,
    direction: RequestDirection,
}

impl<P> FirewallRequest<P>
where
    P: Message + VariantPermission,
{
    pub fn new(variant: P, remote: PeerId, direction: RequestDirection) -> Self {
        FirewallRequest {
            variant,
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

#[derive(Debug, Clone)]
pub enum FirewallPermission {
    None,
    Restricted(PermissionSum),
    All,
}

/// Permission for a specific peer.
#[derive(Debug, Clone)]
pub enum FirewallRule {
    SetDefault {
        direction: RequestDirection,
        permission: FirewallPermission,
    },
    SetRule {
        peer_id: PeerId,
        direction: RequestDirection,
        permission: FirewallPermission,
    },
    RemoveRule {
        peer_id: PeerId,
        direction: RequestDirection,
    },
}

#[derive(Debug, Clone)]
pub struct FirewallConfiguration<P>
where
    P: Message + VariantPermission,
{
    default_in: FirewallPermission,
    default_out: FirewallPermission,
    rules_in: HashMap<PeerId, FirewallPermission>,
    rules_out: HashMap<PeerId, FirewallPermission>,
    marker: PhantomData<P>,
}

impl<P> Default for FirewallConfiguration<P>
where
    P: Message + VariantPermission,
{
    fn default() -> Self {
        FirewallConfiguration {
            default_in: FirewallPermission::None,
            default_out: FirewallPermission::All,
            rules_in: HashMap::new(),
            rules_out: HashMap::new(),
            marker: PhantomData,
        }
    }
}

impl<P> FirewallConfiguration<P>
where
    P: Message + VariantPermission,
{
    pub fn set_default_in(&mut self, default: FirewallPermission) {
        self.default_in = default;
    }

    pub fn set_default_out(&mut self, default: FirewallPermission) {
        self.default_out = default;
    }

    pub fn set_rule(&mut self, peer_id: PeerId, direction: &RequestDirection, permission: FirewallPermission) {
        match direction {
            RequestDirection::In => {
                self.rules_in.insert(peer_id, permission);
            }
            RequestDirection::Out => {
                self.rules_out.insert(peer_id, permission);
            }
        }
    }

    pub fn remove_rule(&mut self, peer_id: &PeerId, direction: &RequestDirection) {
        match direction {
            RequestDirection::In => {
                self.rules_in.remove(peer_id);
            }
            RequestDirection::Out => {
                self.rules_out.remove(peer_id);
            }
        }
    }

    pub fn get_permission(&mut self, peer_id: PeerId, direction: &RequestDirection) -> FirewallPermission {
        match direction {
            RequestDirection::In => self.rules_in.get(&peer_id).unwrap_or(&self.default_in).clone(),
            RequestDirection::Out => self.rules_out.get(&peer_id).unwrap_or(&self.default_out).clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommunicationFirewall<P>
where
    P: Message + VariantPermission,
{
    config: FirewallConfiguration<P>,
}

impl<P> ActorFactory for CommunicationFirewall<P>
where
    P: Message + VariantPermission,
{
    fn create() -> Self {
        CommunicationFirewall {
            config: FirewallConfiguration::default(),
        }
    }
}

impl<P> Actor for CommunicationFirewall<P>
where
    P: Message + VariantPermission,
{
    type Msg = CommunicationFirewallMsg<P>;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            CommunicationFirewallMsg::Request(req) => {
                <CommunicationFirewall<P> as Receive<FirewallRequest<P>>>::receive(self, ctx, req, sender)
            }
            CommunicationFirewallMsg::Rule(rule) => {
                <CommunicationFirewall<P> as Receive<FirewallRule>>::receive(self, ctx, rule, sender)
            }
        }
    }
}

impl<P> Receive<FirewallRule> for CommunicationFirewall<P>
where
    P: Message + VariantPermission,
{
    type Msg = CommunicationFirewallMsg<P>;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: FirewallRule, _sender: Sender) {
        match msg {
            FirewallRule::SetDefault {
                direction: RequestDirection::In,
                permission,
            } => {
                self.config.set_default_in(permission);
            }
            FirewallRule::SetDefault {
                direction: RequestDirection::Out,
                permission,
            } => {
                self.config.set_default_out(permission);
            }
            FirewallRule::SetRule {
                peer_id,
                direction,
                permission,
            } => self.config.set_rule(peer_id, &direction, permission),
            FirewallRule::RemoveRule { peer_id, direction } => self.config.remove_rule(&peer_id, &direction),
        }
    }
}

impl<P> Receive<FirewallRequest<P>> for CommunicationFirewall<P>
where
    P: Message + VariantPermission,
{
    type Msg = CommunicationFirewallMsg<P>;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: FirewallRequest<P>, sender: Sender) {
        let permissions = self.config.get_permission(msg.remote, &msg.direction);
        let res = match permissions {
            FirewallPermission::None => FirewallResponse::Reject,
            FirewallPermission::All => FirewallResponse::Accept,
            FirewallPermission::Restricted(permissions) => {
                if msg.variant.is_permitted(permissions) {
                    FirewallResponse::Accept
                } else {
                    FirewallResponse::Reject
                }
            }
        };
        if let Some(sender) = sender {
            let _ = sender.try_tell(res, None);
        }
    }
}

// Wrapped message type of the RestrictConnectionFirewall actor
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum CommunicationFirewallMsg<P: Message + VariantPermission> {
    // Query from CommunicationActor for approval of a connection or request message.
    Request(FirewallRequest<P>),
    // Set connection permission for a specific peer.
    Rule(FirewallRule),
}

impl<P: Message + VariantPermission> From<FirewallRequest<P>> for CommunicationFirewallMsg<P> {
    fn from(ty: FirewallRequest<P>) -> Self {
        CommunicationFirewallMsg::Request(ty)
    }
}

impl<P: Message + VariantPermission> From<FirewallRule> for CommunicationFirewallMsg<P> {
    fn from(ty: FirewallRule) -> Self {
        CommunicationFirewallMsg::Rule(ty)
    }
}

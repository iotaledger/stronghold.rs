// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::PeerId;
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
//
#[derive(Debug, Clone)]
pub struct FirewallConfiguration {
    default_in: FirewallPermission,
    default_out: FirewallPermission,
    rules_in: HashMap<PeerId, FirewallPermission>,
    rules_out: HashMap<PeerId, FirewallPermission>,
}

impl Default for FirewallConfiguration {
    fn default() -> Self {
        FirewallConfiguration {
            default_in: FirewallPermission::None,
            default_out: FirewallPermission::All,
            rules_in: HashMap::new(),
            rules_out: HashMap::new(),
        }
    }
}

impl FirewallConfiguration {
    pub fn new(default_in: FirewallPermission, default_out: FirewallPermission) -> FirewallConfiguration {
        FirewallConfiguration {
            default_in,
            default_out,
            rules_in: HashMap::new(),
            rules_out: HashMap::new(),
        }
    }

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

    pub fn is_permitted<Req: VariantPermission>(
        &self,
        variant: Req,
        peer_id: PeerId,
        direction: RequestDirection,
    ) -> bool {
        let permissions = match direction {
            RequestDirection::In => self.rules_in.get(&peer_id).unwrap_or(&self.default_in).clone(),
            RequestDirection::Out => self.rules_out.get(&peer_id).unwrap_or(&self.default_out).clone(),
        };
        match permissions {
            FirewallPermission::None => false,
            FirewallPermission::All => true,
            FirewallPermission::Restricted(permissions) => variant.is_permitted(permissions),
        }
    }
}

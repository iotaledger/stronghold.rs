// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::PeerId;
use std::collections::HashMap;

/// The permission value for request variants.
/// It is a  bit that is set at a certain index, therefore the value is always a power of 2.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionValue(u32);

impl PermissionValue {
    /// Create a new permission value for an index, max allowed index is 31.
    /// The value equals 2 to the power of the index.
    /// For index > 31 the value will result in O, and [`PermissionSum::permits`] will always return false.
    pub fn new(index: u8) -> Self {
        let value = 1u32 << index;
        PermissionValue(value)
    }

    fn value(&self) -> u32 {
        self.0
    }
}

impl PartialEq<u32> for PermissionValue {
    fn eq(&self, other: &u32) -> bool {
        self.value() == *other
    }
}

/// The sum of allowed permissions.
/// This is using the same concepts as e.g. permission values in Unix systems.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionSum(u32);

impl PermissionSum {
    /// No values are allowed.
    pub fn none() -> Self {
        PermissionSum(0u32)
    }

    /// All values are allowed.
    pub fn all() -> Self {
        PermissionSum(u32::MAX)
    }

    /// Adds a new value to the sum and therefore allows this value.
    pub fn add_permission(self, other: PermissionValue) -> Self {
        let sum = self.value() | other.value();
        PermissionSum(sum)
    }

    /// Remove a certain value from the sum to remove permission.
    pub fn remove_permission(self, other: PermissionValue) -> Self {
        let sub = self.value() & !other.value();
        PermissionSum(sub)
    }

    /// Check if the sum includes this value i.g. if a certain bit is set.
    pub fn permits(&self, v: &PermissionValue) -> bool {
        self.value() & v.value() != 0
    }

    fn value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for PermissionSum {
    fn from(value: u32) -> Self {
        PermissionSum(value)
    }
}

impl PartialEq<u32> for PermissionSum {
    fn eq(&self, other: &u32) -> bool {
        self.value() == *other
    }
}

/// The permission value for the different variants of an enum.
/// This allows permitting specific variants of an enum while prohibiting others.
/// In structs or unions, it should default to PermissionValue(1)
pub trait VariantPermission {
    fn permission(&self) -> PermissionValue;
}

/// Convert an element to implement permissions.
pub trait ToPermissionVariants<P: VariantPermission> {
    fn to_permissioned(&self) -> P;
}

impl<T: VariantPermission + Clone> ToPermissionVariants<T> for T {
    fn to_permissioned(&self) -> T {
        self.clone()
    }
}

/// The direction of a [`CommunicationRequest::RequestMsg`] that firewall receives.
#[derive(Debug, Clone)]
pub enum RequestDirection {
    /// Incoming request from a remote peer to the local system.
    In,
    /// Outgoing request from the local system to a remote peer.
    Out,
}

/// Permission that is set in the Firewall.
/// In case of [`FirewallPermission::Restricted`], only selected variants in a enum are allowed,
/// the [`VariantPermission`] of the request message is used for each individual request to validate it.
#[derive(Debug, Clone)]
pub enum FirewallPermission {
    None,
    Restricted(PermissionSum),
    All,
}

/// Configure the firewall.
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

// Configuration of the firewall in the Swarm Task
#[derive(Debug, Clone)]
pub(super) struct FirewallConfiguration {
    // Default for incoming requests if no rule is set for a peer.
    default_in: FirewallPermission,
    // Default for outgoing requests if no rule is set for a peer.
    default_out: FirewallPermission,
    // Rules for incoming request from specific peers.
    rules_in: HashMap<PeerId, FirewallPermission>,
    // Rules for outgoing request to specific peers.
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

    // Uses a rule if one is specified for that peer, otherwise use default.
    // In case of FirewallPermission::Restricted, the permission is checked for the required permissions of the specific
    // request variant.
    pub fn is_permitted<Req: ToPermissionVariants<P>, P: VariantPermission>(
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
            FirewallPermission::Restricted(sum) => sum.permits(&variant.to_permissioned().permission()),
        }
    }
}

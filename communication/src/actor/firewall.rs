// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use communication_macros::RequestPermissions;
use libp2p::PeerId;
use std::collections::HashMap;

/// The permission value for request variants.
/// It is a  bit that is set at a certain index, therefore the value is always a power of 2.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PermissionValue(u32);

impl PermissionValue {
    /// Create a new permission value for an index, the value equals 2 to the power of the index.
    /// Max allowed index is 31, otherwise [`None`] will be returned.
    pub fn new(index: u8) -> Option<Self> {
        if index < 32 {
            let value = 1u32 << index;
            Some(PermissionValue(value))
        } else {
            None
        }
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FirewallPermission(u32);

impl FirewallPermission {
    /// No values are allowed.
    pub fn none() -> Self {
        FirewallPermission(0u32)
    }

    /// All values are allowed.
    pub fn all() -> Self {
        FirewallPermission(u32::MAX)
    }

    /// Adds a new value to the sum and therefore allows this value.
    pub fn add_permission(self, other: &PermissionValue) -> Self {
        let sum = self.value() | other.value();
        FirewallPermission(sum)
    }
    /// Adds a new value to the sum and therefore allows this value.
    pub fn add_permissions<'a>(self, permissions: impl IntoIterator<Item = &'a PermissionValue>) -> Self {
        permissions.into_iter().fold(self, |acc, curr| acc.add_permission(curr))
    }

    /// Remove a certain value from the sum to remove permission.
    pub fn remove_permission(self, other: &PermissionValue) -> Self {
        let sub = self.value() & !other.value();
        FirewallPermission(sub)
    }

    /// Remove a certain value from the sum to remove permission.
    pub fn remove_permissions<'a>(self, permissions: impl IntoIterator<Item = &'a PermissionValue>) -> Self {
        permissions
            .into_iter()
            .fold(self, |acc, curr| acc.remove_permission(curr))
    }

    /// Check if the sum includes this value i.g. if a certain bit is set.
    pub fn permits(&self, v: &PermissionValue) -> bool {
        self.value() & v.value() != 0
    }

    fn value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for FirewallPermission {
    fn from(value: u32) -> Self {
        FirewallPermission(value)
    }
}

impl PartialEq<u32> for FirewallPermission {
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

/// Configure the firewall.
#[derive(Debug, Clone)]
pub enum FirewallRule {
    /// Set new rules either for specific peers, or the default rule.
    SetRules {
        direction: RequestDirection,
        peers: Vec<PeerId>,
        set_default: bool,
        permission: FirewallPermission,
    },
    /// Add specific permissions for certain peers and optionally also to the default rule.
    AddPermissions {
        direction: RequestDirection,
        peers: Vec<PeerId>,
        change_default: bool,
        permissions: Vec<PermissionValue>,
    },
    /// Remove specific permissions from certain peers and optionally also from the default rule.
    RemovePermissions {
        direction: RequestDirection,
        peers: Vec<PeerId>,
        change_default: bool,
        permissions: Vec<PermissionValue>,
    },
    /// Remove a rule for a specific peer, which results in using the default rule for that peer.
    RemoveRule {
        peers: Vec<PeerId>,
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
            default_in: FirewallPermission::none(),
            default_out: FirewallPermission::all(),
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

    pub fn get_default(&mut self, direction: &RequestDirection) -> FirewallPermission {
        match direction {
            RequestDirection::In => self.default_in,
            RequestDirection::Out => self.default_out,
        }
    }

    pub fn set_default(&mut self, direction: &RequestDirection, default: FirewallPermission) {
        match direction {
            RequestDirection::In => self.default_in = default,
            RequestDirection::Out => self.default_out = default,
        }
    }

    pub fn has_rule(&mut self, peer_id: &PeerId, direction: &RequestDirection) -> bool {
        match direction {
            RequestDirection::In => self.rules_in.contains_key(peer_id),
            RequestDirection::Out => self.rules_in.contains_key(peer_id),
        }
    }

    pub fn get_rule(&mut self, peer_id: &PeerId, direction: &RequestDirection) -> Option<FirewallPermission> {
        match direction {
            RequestDirection::In => self.rules_in.get(peer_id).copied(),
            RequestDirection::Out => self.rules_out.get(peer_id).copied(),
        }
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
    // The firewall permission is checked for the required permissions of the specific request variant.
    pub fn is_permitted<Req: ToPermissionVariants<P>, P: VariantPermission>(
        &self,
        variant: &Req,
        peer_id: &PeerId,
        direction: RequestDirection,
    ) -> bool {
        let permissions = match direction {
            RequestDirection::In => *self.rules_in.get(peer_id).unwrap_or(&self.default_in),
            RequestDirection::Out => *self.rules_out.get(peer_id).unwrap_or(&self.default_out),
        };
        permissions.permits(&variant.to_permissioned().permission())
    }
}

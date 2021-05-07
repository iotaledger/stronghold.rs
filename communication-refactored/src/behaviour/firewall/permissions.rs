// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use stronghold_derive::RequestPermissions;
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

    pub fn is_no_permissions(&self) -> bool {
        self.0 == 0
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
pub trait VariantPermission: 'static + Send + Sync + Clone {
    fn permission(&self) -> PermissionValue;
}

/// Convert an element to implement permissions.
pub trait ToPermissionVariants<P: VariantPermission> {
    fn to_permissioned(&self) -> P;

    fn permission_value(&self) -> PermissionValue {
        self.to_permissioned().permission()
    }
}
impl<T: VariantPermission + Clone> ToPermissionVariants<T> for T {
    fn to_permissioned(&self) -> T {
        self.clone()
    }
}

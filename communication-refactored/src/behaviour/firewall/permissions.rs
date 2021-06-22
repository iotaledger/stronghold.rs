// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use stronghold_derive::RequestPermissions;

/// The permission value for request variants.
/// This is realized as a bit set at a certain index, hence the value is always a power of 2.
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

/// The sum of allowed  [`PermissionValue`]s.
/// This is realized as different bits set in the integer, analogous to file permissions in Unix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FirewallPermission(u32);

impl FirewallPermission {
    /// Create new [`FirewallPermission`] with no permissions.
    pub fn none() -> Self {
        FirewallPermission(0u32)
    }

    /// Check if no values are allowed.
    pub fn is_no_permissions(&self) -> bool {
        self.0 == 0
    }

    /// Create new [`FirewallPermission`] with max permission; all  [`PermissionValue`]s are allowed.
    pub fn all() -> Self {
        FirewallPermission(u32::MAX)
    }

    /// Adds new [`PermissionValue`] to the sum, hence allows these values.
    pub fn add_permissions<'a>(self, permissions: impl IntoIterator<Item = &'a PermissionValue>) -> Self {
        let p = permissions.into_iter().fold(self.0, |acc, curr| acc | curr.value());
        FirewallPermission(p)
    }

    /// Removes  [`PermissionValue`] from the sum to remove permission.
    pub fn remove_permissions<'a>(self, permissions: impl IntoIterator<Item = &'a PermissionValue>) -> Self {
        let p = permissions.into_iter().fold(self.0, |acc, curr| acc & !curr.value());
        FirewallPermission(p)
    }

    /// Check if the sum includes this [`PermissionValue`] i.g. if a certain bit is set.
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
/// In structs or unions, it should default to [`PermissionValue(1)`].
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

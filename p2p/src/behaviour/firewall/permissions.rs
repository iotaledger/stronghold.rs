// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Trait and macros that may be used in the firewall rule [`Rule::Restricted`] to restrict request
//! enums based on the variant.
//!
//! A [`PermissionValue`] value is a u32 integer value that is some power of 2, e.g. 1, 2, 4, 8, ..etc.
//! Following the same concept as Unix permissions multiple  [`PermissionValue`] can be added to a sum
//! [`FirewallPermission`], that unambiguously identifies what [`PermissionValue`]s were set.
//!
//! The [`VariantPermission`] can be implemented for a request enum to give each variant a different
//! [`PermissionValue`]. It can be derived with the [`RequestPermissions`] macro, which:
//! 1. implements [`PermissionValue`] for the type
//! 2. generates a trimmed version of the type (`<type-name>Permissions`) that has the same variants
//!    but without values:
//!
//! ```
//! # use p2p::{
//! #   firewall::{
//! #       permissions::{FirewallPermission, PermissionValue, RequestPermissions, VariantPermission},
//! #       FirewallRules, FwRequest, Rule,
//! #   },
//! #   ChannelSinkConfig, EventChannel, StrongholdP2p, StrongholdP2pBuilder,
//! # };
//! # use futures::channel::mpsc;
//! # use std::{error::Error, marker::PhantomData};
//! # use serde::{Serialize, Deserialize};
//! # type MessageResponse = String;
//! #
//! # async fn test() -> Result<(), Box<dyn Error>> {
//! // The derive macro generates:
//! // ```
//! // enum MessagePermission {
//! //     Ping,
//! //     Message,
//! //     Other,
//! // }
//! // ```
//! //
//! #[derive(Debug, RequestPermissions, Serialize, Deserialize)]
//! enum Message {
//!     Ping,
//!     Message(String),
//!     Other(Vec<u8>),
//! }
//!
//! assert_eq!(MessagePermission::Ping.permission(), 1);
//! assert_eq!(MessagePermission::Message.permission(), 2);
//! assert_eq!(MessagePermission::Other.permission(), 4);
//!
//! // Create rule that only permits ping-messages.
//! let rule: Rule<MessagePermission> = Rule::Restricted {
//!     restriction: |rq: &MessagePermission| {
//!         let allowed_variant = FirewallPermission::none().add_permissions([&MessagePermission::Ping.permission()]);
//!         allowed_variant.permits(&rq.permission())
//!     },
//!     _maker: PhantomData,
//! };
//!
//! # let (firewall_tx, firewall_rx) = mpsc::channel(10);
//! # let (request_tx, request_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);
//! #
//! let builder = StrongholdP2pBuilder::new(firewall_tx, request_tx, None)
//!     .with_firewall_default(FirewallRules::new(Some(rule), None));
//!
//! // Use `MessagePermissions` in StrongholdP2p as type for firewall requests.
//! let p2p: StrongholdP2p<Message, MessageResponse, MessagePermission> = builder.build().await?;
//! #
//! # Ok(())
//! # }
//! ```

pub use stronghold_derive::RequestPermissions;

/// The permission value for request variants.
/// This is realized as a bit set at a certain index, hence the value is always a power of 2.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PermissionValue(u32);

impl PermissionValue {
    /// Create a new permission value for an index, the value equals 2^index.
    /// Max allowed index is 31, otherwise [`None`] will be returned.
    ///
    /// E.g.
    /// - PermissionValue::new(0) -> PermissionValue(1)
    /// - PermissionValue::new(1) -> PermissionValue(2)
    /// - PermissionValue::new(2) -> PermissionValue(4)
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

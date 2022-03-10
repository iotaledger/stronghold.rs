// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]
#![allow(clippy::from_over_into)]
#![allow(clippy::upper_case_acronyms)]

/// An interface for implementing the stronghold engine. Using the Actix Actor model, this library provides a
/// mechanism to manage secret data between multiple users. Stronghold may be accessed via the `Stronghold`
/// object. The interface contains methods to access the secure runtime environment and methods to write to the
/// Stronghold. Each Stronghold contains a collection of versioned records, identified as Vaults. Each Vault
/// contains a set of versioned records of like data. Multiple clients can be spawned with Stronghold, each of
/// which can hold multiple vaults (See the `Location` API for more details). The Stronghold interface also
/// contains a generic insecure key/value store which can be accessed as a `Store`. Each client contains a single
/// store and the same location may be used across multiple clients.
// TODO: Synchronization via 4th actor and status type.
// TODO: Add documentation
// TODO: Handshake
// TODO: ~Adapt Documentation~
// TODO: ~Add supervisors~
// TODO: ~~O(1) comparison for IDS.~~
// TODO: ~~Add ability to name snapshots~~
// TODO: ~~Add ability to read and revoke records not on the head of the chain.~~
// TODO: Add Reference types for the RecordIds and VaultIds to expose to the External programs.
// TODO: Add Handshake Messages.
// TODO: Add Responses for each Message.
// TODO: Remove #[allow(dead_code)]
mod actors;
mod interface;
mod internals;
pub mod procedures;
mod state;
mod utils;

// Tests exist as a sub-module because they need to be able to test internal concepts without exposing them publicly.
#[cfg(test)]
mod tests;

pub use crate::{
    interface::{ActorError, FatalEngineError, Stronghold, StrongholdResult},
    internals::Provider,
    state::snapshot::{ReadError, WriteError},
    utils::{Location, StrongholdFlags, VaultFlags},
};
pub use engine::{
    snapshot::{
        files::{home_dir, snapshot_dir},
        kdf::naive_kdf,
        Key,
    },
    vault::{RecordHint, RecordId},
};
#[cfg(feature = "p2p")]
pub mod p2p {
    pub use crate::{
        actors::network_messages::SwarmInfo,
        interface::{P2pError, P2pResult, SpawnNetworkError},
        state::p2p::{
            ClientPermissions, FirewallChannel, FirewallChannelSender, NetworkConfig, Permissions, PermissionsRequest,
            Request, ShRequest, ShResult,
        },
    };
    pub use p2p::{
        firewall::Rule, identity, DialErr, ListenErr, ListenRelayErr, Multiaddr, OutboundFailure, PeerId,
        RelayNotSupported,
    };
}

pub use actix::MailboxError;

#[macro_export]
macro_rules! enum_from_inner {
    ($($Enum:ident$(::<$G:ident>)?::$T:ident),+ $MEnum:ident$(::<$H:ident>)?::$MT:ident from $CEnum:ty) => {
        impl$(<H>)? From<$CEnum> for $MEnum$(<H>)? {
            fn from(t: $CEnum) -> Self {
                $MEnum::$MT(t.into())
            }
        }
        $(
            impl$(<$G>)? From<$CEnum> for $Enum$(<$G>)? {
                fn from(t: $CEnum) -> Self {
                    let m: $MEnum$(<H>)? = t.into()
                    $Enum::$T(m.into())
                }
            }
        )*
    };
    ($($Enum:ident$(::<$G:ident>)?::$T:ident),+ from $CEnum:ty) => {
        $(
            impl$(<$G>)? From<$CEnum> for $Enum$(<$G>)? {
                fn from(t: $CEnum) -> Self {
                    $Enum::$T(t.into())
                }
            }
        )*
    };
    ($Enum:ident$(<$G:ident>)? from $TInner:ident$(<$H:ident>)?) => {
        impl$(<$G>)? From<$TInner$(<$H>)?> for $Enum$(<$G>)? {
            fn from(t: $TInner$(<$H>)?) -> Self {
                $Enum::$TInner(t)
            }
        }
    };
}

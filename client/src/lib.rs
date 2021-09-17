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
use thiserror::Error as DeriveError;

mod actors;
mod interface;
mod internals;
mod procedures;
mod state;
mod utils;

// Tests exist as a sub-module because they need to be able to test internal concepts without exposing them publicly.
#[cfg(test)]
mod tests;

pub use crate::{
    interface::Stronghold,
    internals::Provider,
    procedures::*,
    utils::{Location, ResultMessage, StatusMessage, StrongholdFlags, VaultFlags},
};

#[cfg(feature = "p2p")]
pub mod p2p {
    pub use crate::actors::p2p::{NetworkConfig, SwarmInfo};
    pub use p2p::{firewall::Rule, Multiaddr, PeerId};
}

pub use engine::{
    snapshot::{
        files::{home_dir, snapshot_dir},
        kdf::naive_kdf,
        Key,
    },
    vault::RecordId,
};

pub use engine::vault::RecordHint;

/// TODO: Should be replaced with proper errors.
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

#[macro_export]
macro_rules! unwrap_or_err (
    ($expression:expr) => {
        match $expression {
            Ok(ok) => ok,
            Err(err) => return ResultMessage::Error(err.to_string())
        }
    };
    ($expression:expr, $error:literal) => {
        match $expression {
            Ok(ok) => ok,
            Err(_) => return ResultMessage::Error($error.to_string()),
        }
    };
    (Option, $expression:expr, $error:literal) => {
        match $expression.as_ref() {
            Some(item) => item,
            None => return ResultMessage::Error($error.to_string())
        }
    };
);

#[macro_export]
macro_rules! unwrap_result_msg (
    ($expr:expr) => {
        unwrap_or_err!(unwrap_or_err!($expr))
    };
);

#[macro_export]
macro_rules! enum_from_inner {
    ($($Enum:ident::$T:ident),+ from $CEnum:ident) => {
        $(
            impl From<$CEnum> for $Enum {
                fn from(t: $CEnum) -> Self {
                    $Enum::$T(t.into())
                }
            }
        )*
    };
    ($Enum:ident from $TInner:ident) => {
        impl From<$TInner> for $Enum {
            fn from(t: $TInner) -> Self {
                $Enum::$TInner(t)
            }
        }
    };
}

/// Stronghold Client Result Type.
pub type Result<T> = anyhow::Result<T, Error>;

/// Stronghold Client error block.
#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Id Error")]
    IDError,

    #[error("Engine Error: {0}")]
    EngineError(#[from] engine::Error),

    #[error("Id Conversion Error ({0})")]
    IdConversionError(String),

    #[error("Path Error: ({0})")]
    PathError(String),

    #[error("Keystore Access Error: ({0})")]
    KeyStoreError(String),

    #[error("Could not load client by path ({0})")]
    LoadClientByPathError(String),
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

/// An interface for implementing the stronghold engine. Using the Riker Actor model, this library provides a
/// mechanism to manage secret data between multiple users. Stronghold may be accessed via the `Stronghold`
/// object. The interface contains methods to access the secure runtime environment and methods to write to the
/// Stronghold. Each Stronghold contains a collection of versioned records, identified as Vaults. Each Vault
/// contains a set of versioned records of like data. Multiple clients can be spawned with Stronghold, each of
/// which can hold multiple vaults (See the `Location` API for more details). The Stronghold interface also
/// contains a generic insecure key/value store which can be accessed as a `Store`. Each client contains a single
/// store and the same location may be used across multiple clients.
// TODO: Synchronization via 4th actor and status type.
// TODO: Add supervisors
// TODO: Add documentation
// TODO: Handshake
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
mod state;
mod utils;

#[cfg(test)]
mod tests;

use crate::utils::{ClientId, VaultId};

pub use crate::{
    actors::{ProcResult, Procedure, SLIP10DeriveInput},
    interface::Stronghold,
    internals::Provider,
    utils::{Location, ResultMessage, StatusMessage, StrongholdFlags, VaultFlags},
};

pub use engine::snapshot::{
    files::{home_dir, snapshot_dir},
    kdf::{naive_kdf, recommended_kdf},
    Key,
};

pub use engine::vault::RecordHint;

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

pub type Result<T> = anyhow::Result<T, Error>;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Id Error")]
    IDError,
    #[error("Vault Error: {0}")]
    VaultError(#[from] engine::vault::Error),
    #[error("Snapshot Error: {0}")]
    SnapshotError(#[from] engine::snapshot::Error),
}

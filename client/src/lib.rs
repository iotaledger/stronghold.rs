// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: Synchronization via 4th actor and status type.
// TODO: Add supervisors
// TODO: Add documentation
// TODO: Encrypted Return Channel
// TODO: Handshake
// TODO: O(1) comparison for IDS.
// TODO: Remove #[allow(dead_code)]s.
// TODO: ~~Add ability to name snapshots~~
// TODO: ~~Add ability to read and revoke records not on the head of the chain.~~
// TODO: Add Reference types for the RecordIds and VaultIds to expose to the External programs.
// TODO: Add Handshake Messages.
// TODO: Add Responses for each Message.

use thiserror::Error as DeriveError;

mod actors;
mod bucket;
mod client;
mod interface;
mod internals;
mod key_store;
mod snapshot;
mod utils;

use crate::utils::{ClientId, VaultId};

pub use crate::{
    interface::Stronghold,
    internals::Provider,
    utils::{StatusMessage, StrongholdFlags, VaultFlags},
};

pub use engine::snapshot::{home_dir, naive_kdf, snapshot_dir, Key};

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

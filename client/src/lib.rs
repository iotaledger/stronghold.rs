// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: Synchronization via 4th actor and status type.
// TODO: Add supervisors
// TODO: Add documentation
// TODO: Encrypted Return Channel
// TODO: Handshake
// TODO: O(1) comparison for IDS.

use thiserror::Error as DeriveError;

mod actors;
mod bucket;
mod client;
mod ids;
mod key_store;
mod provider;
mod secret;
mod snapshot;

pub use crate::ids::{ClientId, VaultId};

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
}

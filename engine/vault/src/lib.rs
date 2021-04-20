// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]
#![allow(clippy::upper_case_acronyms)]

//! Vault is an in-memory database specification which is designed to work without a central server. Only the user which
//! holds the associated id and key may modify the data in a vault.  Another owner can take control over the data if
//! they know the id and the key.
//!
//! Data can be added to the chain via a [`DataTransaction`].  The [`DataTransaction`] is associated to the chain
//! through the owner's ID and it contains its own randomly generated ID.
//!
//! Records may also be revoked from the Vault through a [`RevocationTransaction`]. A [`RevocationTransaction`] is
//! created and it references the id of a existing [`DataTransaction`]. The `RevocationTransaction` stages the
//! associated record for deletion. The record is deleted when the [`DbView`] preforms a garbage collection and the
//! [`RevocationTransaction`] is deleted along with it.
use thiserror::Error as DeriveError;

mod base64;
mod crypto_box;
mod types;
pub mod vault;

use runtime::ZeroingAlloc;

pub use crate::{
    base64::{Base64Decodable, Base64Encodable},
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::utils::{ChainId, ClientId, Id, RecordHint, RecordId, VaultId},
    vault::DbView,
};

/// A Zeroing Allocator which wraps the standard memory allocator. This allocator zeroes out memory when it is dropped.
/// Works on any application that imports stronghold.
#[global_allocator]
static ALLOC: ZeroingAlloc<std::alloc::System> = ZeroingAlloc(std::alloc::System);

/// Errors for the Vault Crate
#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Database Error: `{0}`")]
    DatabaseError(String),
    #[error("Version Error: `{0}`")]
    VersionError(String),
    #[error("Chain error: `{0}`")]
    ChainError(String),
    #[error("Base64Error")]
    Base64Error,
    #[error("Base64Error: `{0}`")]
    Base64ErrorDetailed(String),
    #[error("Interface Error")]
    InterfaceError,
    #[error("Other Error")]
    OtherError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(String),
    #[error("Value Error: `{0}`")]
    ValueError(String),
    #[error("Protocol Error: `{0}`")]
    ProtocolError(String),
}

// Crate result type
pub type Result<T> = std::result::Result<T, Error>;

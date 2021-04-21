// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A system for securely managing secrets.
//!
//! This top-level crate contains references to the others that make up
//! the IOTA Stronghold's low-level crates known as "Stronghold-Engine".
//!
//! # Layout
//!
//! This framework is divided into the following crates:
//!
//! - `vault`: logic and abstractions for the storage layer
//! - `snapshot`: method for storing the state of the vault in a file
//! - `store`: a simple unencrypted storage protocol
//!
//! ## WARNING
//!
//! This library has not yet been audited for security, so use at your own peril.
//! Until a formal third-party security audit has taken place, the IOTA Foundation
//! makes no guarantees to the fitness of this library for any purposes.

use thiserror::Error as DeriveError;

use runtime::ZeroingAlloc;

pub mod snapshot;
pub mod store;
pub mod vault;
pub use runtime;

/// A Zeroing Allocator which wraps the standard memory allocator. This allocator zeroes out memory when it is dropped.
/// Works on any application that imports stronghold.
#[global_allocator]
static ALLOC: ZeroingAlloc<std::alloc::System> = ZeroingAlloc(std::alloc::System);

#[derive(Debug, DeriveError)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IoError(#[from] std::io::Error),
    #[error("Snapshot Error: `{0}`")]
    SnapshotError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(crypto::Error),
    #[error("LZ4 Error: `{0}`")]
    Lz4Error(String),
    #[error("TryInto Error: `{0}`")]
    TryIntoError(#[from] std::array::TryFromSliceError),
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
    #[error("Provider Error: `{0}`")]
    ProviderError(String),
    #[error("Value Error: `{0}`")]
    ValueError(String),
    #[error("Protocol Error: `{0}`")]
    ProtocolError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::CryptoError(e)
    }
}

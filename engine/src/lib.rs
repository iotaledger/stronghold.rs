// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![no_std]

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

#[cfg(feature = "std")]
extern crate std;
extern crate alloc;

use core::fmt::{self, Debug, Formatter};

use alloc::{format, string::String};

#[cfg(feature = "std")]
use runtime::ZeroingAlloc;

pub mod snapshot;
#[cfg(feature = "std")]
pub mod store;
pub mod vault;
pub use runtime;

/// A Zeroing Allocator which wraps the standard memory allocator. This allocator zeroes out memory when it is dropped.
/// Works on any application that imports stronghold.
#[cfg(feature = "std")]
#[global_allocator]
static ALLOC: ZeroingAlloc<std::alloc::System> = ZeroingAlloc(std::alloc::System);

pub enum Error {
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    SnapshotError(String),
    CryptoError(crypto::Error),
    Lz4Error(String),
    TryIntoError(core::array::TryFromSliceError),
    DatabaseError(String),
    Base64Error,
    Base64ErrorDetailed(String),
    InterfaceError,
    OtherError(String),
    ProviderError(String),
    ValueError(String),
}

pub type Result<T> = core::result::Result<T, Error>;

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Base64Error => f.write_str("Base64Error"),
            Error::Base64ErrorDetailed(e) => f.write_str(&format!("Base64Error: {}", e)),
            Error::CryptoError(e) => f.write_str(&format!("CryptoError: {}", e)),
            Error::DatabaseError(e) => f.write_str(&format!("DatabaseError: {}", e)),
            Error::InterfaceError => f.write_str("InterfaceError"),
            #[cfg(feature = "std")]
            Error::IoError(e) => f.write_str(&format!("IoError: {}", e)),
            Error::Lz4Error(e) => f.write_str(&format!("Lz4Error: {}", e)),
            Error::OtherError(e) => f.write_str(&format!("OtherError: {}", e)),
            Error::ProviderError(e) => f.write_str(&format!("ProviderError: {}", e)),
            Error::SnapshotError(e) => f.write_str(&format!("SnapshotError: {}", e)),
            Error::TryIntoError(e) => f.write_str(&format!("TryIntoError: {}", e)),
            Error::ValueError(e) => f.write_str(&format!("ValueError: {}", e)),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(e: core::array::TryFromSliceError) -> Self {
        Self::TryIntoError(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[cfg(feature = "std")]
impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::CryptoError(e)
    }
}

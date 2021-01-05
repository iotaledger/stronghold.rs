// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This crate defines and implements the encrypted offline storage format used by
//! the Stronghold ecosystem.
//!
//! The format has a header with version and magic bytes to appease applications
//! wishing to provide file-type detection.
//!
//! The data stored within a snapshot is considered opaque and uses 256 bit keys.
//! It provides recommended ways to derive the snapshot encryption key from a user
//! provided password. The format also allows using an authenticated data
//! bytestring to further protect the offline snapshot files (one might consider
//! using a secondary user password strengthened by an HSM).
//!
//! The current version of the format is using the symmetric XChaCha20 cipher with
//! the Poly1305 message authentication algorithm.
//!
//! Future versions will consider using X25519 to encrypt using an ephemeral key
//! instead of directly using the users key. When the demands for larger
//! snapshot sizes and/or random access is desired one might consider encrypting
//! smaller chunks (B-trees?) or similar using derived ephemeral keys.

mod compression;
pub mod files;
pub mod kdf;

#[cfg(test)]
mod test_utils;

mod logic;
pub use compression::{compress, decompress};
pub use logic::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("Snapshot Error: `{0}`")]
    SnapshotError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(crypto::Error),
    #[error("LZ4 Error: `{0}`")]
    LZ4Error(String),
    #[error("TryInto Error: `{0}`")]
    TryIntoError(#[from] std::array::TryFromSliceError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::CryptoError(e)
    }
}

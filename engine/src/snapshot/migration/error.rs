// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::keys::age;
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum Error {
    /// Can't migrate between selected versions.
    #[error("Can't migrate between selected versions")]
    BadMigrationVersion,
    /// Input snapshot has incorrect/unexpected version.
    #[error("Input snapshot has incorrect/unexpected version")]
    BadSnapshotVersion,
    /// Input file has incorrect format.
    #[error("Input file has incorrect format")]
    BadSnapshotFormat,
    /// Failed to decrypt snapshot: incorrect password or corrupt data.
    #[error("Failed to decrypt snapshot: incorrect password or corrupt data")]
    DecryptFailed,
    /// Failed to decompress snapshot.
    #[error("Failed to decompress snapshot")]
    DecompressFailed,
    /// Authenticated associated data is not supported by snapshot format.
    #[error("Authenticated associated data is not supported by snapshot format")]
    AadNotSupported,
    /// Failed to encrypt.
    #[error("Failed to encrypt")]
    EncryptFailed,
    /// Age format error.
    #[error("Age format error")]
    AgeError(age::Error),
    /// I/O error.
    #[error("I/O error")]
    IoError(std::io::Error),
    /// Crypto error.
    #[error("Crypto error")]
    CryptoError(crypto::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::CryptoError(e)
    }
}

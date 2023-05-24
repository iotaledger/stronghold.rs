// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::keys::age;
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum Error {
    /// Can't migrate between selected versions.
    #[error("can't migrate between selected versions")]
    BadMigrationVersion,
    /// Input snapshot has incorrect/unexpected version.
    #[error("input snapshot has incorrect/unexpected version")]
    BadSnapshotVersion,
    /// Input file has incorrect format.
    #[error("input file has incorrect format")]
    BadSnapshotFormat,
    /// Failed to decrypt snapshot: incorrect password or corrupt data.
    #[error("failed to decrypt snapshot: incorrect password or corrupt data")]
    DecryptFailed,
    /// Failed to decompress snapshot.
    #[error("failed to decompress snapshot")]
    DecompressFailed,
    /// Authenticated associated data is not supported by snapshot format.
    #[error("authenticated associated data is not supported by snapshot format")]
    AadNotSupported,
    /// Failed to generate randomness.
    #[error("failed to generate randomness")]
    RngFailed,
    /// Age format error.
    #[error("age format error")]
    AgeFormatError(age::DecError),
    /// I/O error.
    #[error("I/O error")]
    IoError(std::io::Error),
    /// Crypto error.
    #[error("crypto error")]
    CryptoError(crypto::Error),
}

impl From<age::DecError> for Error {
    fn from(e: age::DecError) -> Self {
        Self::AgeFormatError(e)
    }
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

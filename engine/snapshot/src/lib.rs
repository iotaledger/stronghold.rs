// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod files;
mod kdf;
mod logic;

#[cfg(test)]
mod test_utils;

pub use files::{home_dir, snapshot_dir};
pub use kdf::{naive_kdf, recommended_kdf};
pub use logic::{read, read_from, write, write_to, Key};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("Snapshot Error: `{0}`")]
    SnapshotError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(crypto::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::CryptoError(e)
    }
}

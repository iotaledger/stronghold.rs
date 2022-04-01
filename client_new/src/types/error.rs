// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, RecordError as EngineRecordError, RecordId, VaultError as EngineVaultError, VaultId};
use serde::{de::Error, Deserialize, Serialize};
use thiserror::Error as DeriveError;

use crate::Provider;
use std::io;

#[derive(Debug, DeriveError)]
#[non_exhaustive]
pub enum ClientError {
    #[error("Acquiring lock failed")]
    LockAcquireFailed,

    #[error("No read access")]
    NoReadAccess,

    #[error("No write access")]
    NoWriteAccess,

    #[error("No such value exist for key ({0})")]
    NoValuePresent(String),

    #[error("Inner error occured({0})")]
    Inner(String),

    #[error("Error loading client data. No data present")]
    ClientDataNotPresent,
}

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug)]
pub enum SpawnNetworkError {
    #[error("network already running")]
    AlreadySpawned,

    #[error("no client found for loading the config")]
    ClientNotFound,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Error loading network config: {0}")]
    LoadConfig(String),

    #[error("Error deriving noise-keypair: {0}")]
    DeriveKeypair(String),

    #[error("Inner error occured {0}")]
    Inner(String),
}

pub type VaultError<E> = EngineVaultError<<Provider as BoxProvider>::Error, E>;
pub type RecordError = EngineRecordError<<Provider as BoxProvider>::Error>;

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
#[error("fatal engine error: {0}")]
pub struct FatalEngineError(String);

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupted file: {0}")]
    CorruptedContent(String),

    #[error("invalid file {0}")]
    InvalidFile(String),

    #[error("missing or invalid snapshot key in {0:?} {1:?}")]
    SnapshotKey(VaultId, RecordId),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("BoxProvider error: {0}")]
    Provider(String),

    #[error("Inner error: ({0})")]
    Inner(String),
}

impl From<RecordError> for FatalEngineError {
    fn from(e: RecordError) -> Self {
        FatalEngineError(e.to_string())
    }
}

impl From<String> for FatalEngineError {
    fn from(e: String) -> Self {
        FatalEngineError(e)
    }
}

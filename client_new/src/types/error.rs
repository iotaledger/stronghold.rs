// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::TryLockError;

use engine::vault::{BoxProvider, RecordError as EngineRecordError, RecordId, VaultError as EngineVaultError, VaultId};
use serde::{de::Error, Deserialize, Serialize};
use thiserror::Error as DeriveError;

use crate::Provider;

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

impl<T> From<TryLockError<T>> for ClientError {
    fn from(_: TryLockError<T>) -> Self {
        ClientError::LockAcquireFailed
    }
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{any::Any, convert::Infallible, fmt::Debug, sync::TryLockError};

use engine::{
    snapshot::{ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{BoxProvider, RecordError as EngineRecordError, RecordId, VaultError as EngineVaultError, VaultId},
};
use serde::{de::Error, Deserialize, Serialize};
use thiserror::Error as DeriveError;

use crate::{Client, Provider};
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

    #[error("Engine error occured({0})")]
    Engine(String),

    #[error("BoxProvider error: ({0})")]
    Provider(String),

    #[error("Error loading client data. No data present")]
    ClientDataNotPresent,

    #[error("Connection failure ({0})")]
    ConnectionFailure(String),

    #[error("Snapshot file is missing ({0})")]
    SnapshotFileMissing(String),

    #[error("Illegal key size. Should be ({0})")]
    IllegalKeySize(usize),
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

impl<T> From<TryLockError<T>> for ClientError {
    fn from(_: TryLockError<T>) -> Self {
        ClientError::LockAcquireFailed
    }
}

impl<E: Debug> From<VaultError<E>> for ClientError {
    fn from(e: VaultError<E>) -> Self {
        ClientError::Engine(format!("{:?}", e))
    }
}

impl From<RecordError> for ClientError {
    fn from(e: RecordError) -> Self {
        VaultError::<Infallible>::Record(e).into()
    }
}

impl From<<Provider as BoxProvider>::Error> for ClientError {
    fn from(e: <Provider as BoxProvider>::Error) -> Self {
        ClientError::Provider(format!("{:?}", e))
    }
}

impl From<Box<dyn Any>> for ClientError {
    fn from(b: Box<dyn Any>) -> Self {
        ClientError::Inner("'Any' type error".into())
    }
}

impl From<SnapshotError> for ClientError {
    fn from(se: SnapshotError) -> Self {
        match se {
            SnapshotError::MissingFile(path) => ClientError::SnapshotFileMissing(path),
            SnapshotError::Io(inner) => ClientError::Inner(inner.to_string()),
            SnapshotError::CorruptedContent(inner) => ClientError::Inner(inner),
            SnapshotError::InvalidFile(inner) => ClientError::Inner(inner),
            SnapshotError::SnapshotKey(vault_id, record_id) => ClientError::Inner(format!(
                "Missing or invalid snapshot key vaultid: {:?}, recordid: {:?}",
                vault_id, record_id
            )),
            SnapshotError::Engine(inner) => ClientError::Inner(inner),
            SnapshotError::Provider(inner) => ClientError::Inner(inner),
            SnapshotError::Inner(inner) => ClientError::Inner(inner),
        }
    }
}

pub type VaultError<E> = EngineVaultError<<Provider as BoxProvider>::Error, E>;
pub type RecordError = EngineRecordError<<Provider as BoxProvider>::Error>;

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
#[error("fatal engine error: {0}")]
pub struct FatalEngineError(String);

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
    Engine(String),

    #[error("BoxProvider error: {0}")]
    Provider(String),

    #[error("Snapshot file is missing ({0})")]
    MissingFile(String),

    #[error("Inner error: ({0})")]
    Inner(String),
}

pub type RemoteRecordError = String;

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
pub enum RemoteVaultError {
    #[error("vault `{0:?}` does not exist")]
    VaultNotFound(VaultId),

    #[error("record error: `{0:?}`")]
    Record(RemoteRecordError),
}

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
pub enum RemoteMergeError {
    #[error("parsing snapshot state from bytestring failed: {0}")]
    ReadExported(String),

    #[error("converting snapshot state into bytestring failed: {0}")]
    WriteExported(String),

    #[error("vault error: {0}")]
    Vault(RemoteVaultError),
}

impl From<ClientError> for SnapshotError {
    fn from(e: ClientError) -> Self {
        SnapshotError::Inner(format!("{}", e))
    }
}

impl From<bincode::Error> for SnapshotError {
    fn from(e: bincode::Error) -> Self {
        SnapshotError::CorruptedContent(format!("bincode error: {}", e))
    }
}

impl From<<Provider as BoxProvider>::Error> for SnapshotError {
    fn from(e: <Provider as BoxProvider>::Error) -> Self {
        SnapshotError::Provider(format!("{:?}", e))
    }
}

impl<E: Debug> From<VaultError<E>> for SnapshotError {
    fn from(e: VaultError<E>) -> Self {
        SnapshotError::Engine(format!("{:?}", e))
    }
}

impl From<RecordError> for SnapshotError {
    fn from(e: RecordError) -> Self {
        VaultError::<Infallible>::Record(e).into()
    }
}

impl From<EngineReadError> for SnapshotError {
    fn from(e: EngineReadError) -> Self {
        match e {
            EngineReadError::CorruptedContent(reason) => SnapshotError::CorruptedContent(reason),
            EngineReadError::InvalidFile => SnapshotError::InvalidFile("Not a Snapshot.".into()),
            EngineReadError::Io(io) => SnapshotError::Io(io),
            EngineReadError::UnsupportedVersion { expected, found } => SnapshotError::InvalidFile(format!(
                "Unsupported version: expected {:?}, found {:?}.",
                expected, found
            )),
        }
    }
}

impl From<EngineWriteError> for SnapshotError {
    fn from(e: EngineWriteError) -> Self {
        match e {
            EngineWriteError::Io(io) => SnapshotError::Io(io),
            EngineWriteError::CorruptedData(e) => SnapshotError::CorruptedContent(e),
            EngineWriteError::GenerateRandom(_) => SnapshotError::Io(std::io::ErrorKind::Other.into()),
        }
    }
}

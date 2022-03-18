// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, RecordError as EngineRecordError, VaultError as EngineVaultError};
use serde::de::Error;
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
}

pub type VaultError<E> = EngineVaultError<<Provider as BoxProvider>::Error, E>;

pub type RecordError = EngineRecordError<<Provider as BoxProvider>::Error>;

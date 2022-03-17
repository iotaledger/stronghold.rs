// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

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
}

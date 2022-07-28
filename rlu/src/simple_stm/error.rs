// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError, PartialEq)]
pub enum TxError {
    #[error("Transaction failed")]
    Failed,

    #[error("TVar is locked")]
    LockPresent,

    #[error("Transactional version has overflown")]
    VersionOverflow,

    #[error("The Transaction is locked")]
    TransactionLocked,

    #[error("Object is stale")]
    StaleObject,

    #[error("Transactable Variable has wrong version")]
    VersionMismatch,
}

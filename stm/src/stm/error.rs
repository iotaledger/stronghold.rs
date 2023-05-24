// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError, PartialEq, Eq)]
pub enum TxError {
    #[error("transaction failed")]
    Failed,

    #[error("TVar is locked")]
    LockPresent,

    #[error("transactional version has overflown")]
    VersionOverflow,

    #[error("the transaction is locked")]
    TransactionLocked,

    #[error("object is stale")]
    StaleObject,

    #[error("transactable variable has wrong version")]
    VersionMismatch,

    #[error("shared value has been casted as the wrong type")]
    SharedValueWrongTypeConversion,
}

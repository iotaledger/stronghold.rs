// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError, PartialEq, Eq)]
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

    #[error("Shared value has been casted as the wrong type")]
    SharedValueWrongTypeConversion,
}

// Macro enabling to handle Result easier in a transaction
#[macro_export]
macro_rules! tx_unwrap {
    ($res:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => { return Ok(Err(e)); },
        }
    };
}


// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum TxError {
    #[error("Transaction failed")]
    Failed,

    #[error("Transaction is locked")]
    LockPresent,

    #[error("Transactional version has overflown")]
    VersionOverflow,
}

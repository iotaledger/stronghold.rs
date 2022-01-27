// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum TransactionError {
    #[error("Transaction failed {0}")]
    Failed(String),
}

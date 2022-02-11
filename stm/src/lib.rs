// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Asynchronous Software Transactional Memory
//!
//! prose ...
#![allow(unused_variables, dead_code, clippy::type_complexity)]

pub mod ctrl;
pub mod errors;
pub mod transaction;
pub mod types;

/// TODO: This mod should be replaced by the upcoming memory features in the runtime!
pub mod boxedalloc;

pub use errors::TransactionError;
use transaction::Strategy;
pub use transaction::Transaction;
pub use types::{TLog, TVar};

/// TODO: this should be replaced by the upcoming memory features in the runtime!
pub use boxedalloc::LockedMemory;

/// This creates an asynchronous operation that runs atomically inside a transaction. Shared
/// memory must be passed as [`TVar`] to read from and write to it. The transaction is retried
/// until it succeeds. As of now, this could hang the execution if certain edge cases are being hit:
/// - interleaving reads and writes, blocking each other.
pub async fn transactional<T, F>(program: F) -> Result<(), TransactionError>
where
    T: Send + Sync + LockedMemory,
    F: Fn(&Transaction<T>) -> Result<(), TransactionError> + Send + 'static,
{
    Transaction::with_strategy(program, Strategy::Retry).await
}

/// This creates an asynchronous operation that runs atomically inside a transaction. Shared
/// memory must be passed as [`TVar`] to read from and write to it. The transaction is aborted
/// if the commit to shared memory fails
pub async fn single<T, F>(program: F) -> Result<(), TransactionError>
where
    T: Send + Sync + LockedMemory,
    F: Fn(&Transaction<T>) -> Result<(), TransactionError> + Send + 'static,
{
    Transaction::with_strategy(program, Strategy::Abort).await
}

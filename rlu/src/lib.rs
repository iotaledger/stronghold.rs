// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Read-Log-Update
//!
//! prose ...
#![allow(unused_variables, dead_code, clippy::type_complexity)]

pub mod nb;
pub mod rlu;

pub use nb::{NonBlockingQueue, NonBlockingStack, Queue, Stack};
pub use rlu::{RLUVar, RluContext, TransactionError, RLU};

// This creates an asynchronous operation that runs atomically inside a transaction. Shared
// memory must be passed as [`TVar`] to read from and write to it. The transaction is retried
// until it succeeds. As of now, this could hang the execution if certain edge cases are being hit:
// - interleaving reads and writes, blocking each other.
// pub async fn transactional<T, F>(program: F) -> Result<(), TransactionError>
// where
//     T: Send + Sync + LockedMemory,
//     F: Fn(&Transaction<T>) -> Result<(), TransactionError> + Send + 'static,
// {
//     Transaction::with_strategy(program, Strategy::Retry).await
// }

// This creates an asynchronous operation that runs atomically inside a transaction. Shared
// memory must be passed as [`TVar`] to read from and write to it. The transaction is aborted
// if the commit to shared memory fails
// pub async fn single<T, F>(program: F) -> Result<(), TransactionError>
// where
//     T: Send + Sync + LockedMemory,
//     F: Fn(&Transaction<T>) -> Result<(), TransactionError> + Send + 'static,
// {
//     Transaction::with_strategy(program, Strategy::Abort).await
// }

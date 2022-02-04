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
pub use boxedalloc::BoxedMemory;

/// This creates an asynchronous operation that runs atomically inside a transaction. Shared
/// memory must be passed as [`TVar`] to read from and write to it. The transaction is retried
/// until it succeeds. As of now, this could hang the execution if certain edge cases are being hit:
/// - interleaving reads and writes, blocking each other.
///
///
/// # use stronghold_stm::*;
///
/// #[tokio::main]
/// async fn main() {
///     let var = TVar::new(0);
///     transactional(|tx| {
///         let v2 = var.clone();
///         async move {
///             let mut inner = tx.read(&v2).await?;
///             inner = inner + 10;
///             tx.write(inner, &v2).await?;
///             Ok(())
///         }
///     })
///     .await;
///     assert_eq!(var.read_atomic().expect(""), 10);
/// }
pub async fn transactional<T, F>(program: F) -> Result<(), TransactionError>
where
    T: Send + Sync + BoxedMemory,
    F: Fn(&Transaction<T>) -> Result<(), TransactionError> + Send + 'static,
{
    Transaction::with_func_strategy(program, Strategy::Retry).await
}

// /// This creates an asynchronous operation that runs atomically inside a transaction. Shared
// /// memory must be passed as [`TVar`] to read from and write to it. The transaction is aborted
// /// if the commit to shared memory fails
// ///
// /// ```
// /// # use stronghold_stm::*;
// ///
// /// #[tokio::main]
// /// async fn main() {
// ///     let var = TVar::new(0);
// ///     assert!(single(|tx| {
// ///         let v2 = var.clone();
// ///         async move {
// ///             let mut inner = tx.read(&v2).await?;
// ///             inner = inner + 10;
// ///             tx.write(inner, &v2).await?;
// ///             Ok(())
// ///         }
// ///     })
// ///     .await
// ///     .is_ok());
// ///     assert_eq!(var.read_atomic().expect(""), 10);
// /// }
// /// ```
// pub async fn single<W, T, F>(program: F) -> Result<(), TransactionError>
// where
//     W: Future<Output = Result<T, TransactionError>> + Send + 'static,
//     T: Send + Sync + BoxedMemory,
//     F: Fn(Arc<Transaction<T>>) -> W,
// {
//     Transaction::with_func_strategy(program, transaction::Strategy::Abort).await
// }

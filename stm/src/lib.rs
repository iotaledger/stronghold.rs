// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Asynchronous Software Transactional Memory
//!
//! prose ...
#![allow(unused_variables, dead_code)]

pub mod ctrl;
pub mod errors;
pub mod transaction;
pub mod types;

/// TODO: This mod should be replaced by the upcoming memory features in the runtime!
pub mod boxedalloc;

use std::future::Future;

pub use errors::TransactionError;
pub use transaction::Transaction;
pub use types::{TLog, TVar};

/// TODO: this should be replaced by the upcoming memory features in the runtime!
pub use boxedalloc::BoxedMemory;

/// This creates an asynchronous operation that runs atomically inside a transaction
///
/// ```
/// # use stronghold_stm::*;
///
/// #[tokio::main]
/// async fn main() {
///     let var: TVar<usize> = TVar::new(0);
///     let var_clone = var.clone();
///     let r1 = tokio::spawn(atomically(|tx| async move {
///         let mut inner: usize = var_clone.read(&tx).await?;
///         inner = inner + 10;
///         var_clone.write(inner, &tx).await?;
///         Ok(())
///     }));
///     let result = r1.await.expect("Unable to join task").expect("Transaction failed");
///     assert_eq!(result, 10);
/// }
/// ```
pub async fn atomically<W, T, F>(_program: F) -> Result<T, TransactionError>
where
    F: FnOnce(Transaction<T>) -> W,
    T: Send + Sync + BoxedMemory,
    W: Future<Output = Result<(), TransactionError>>,
{
    Transaction::with_func(_program).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_transaction() {
        let var: TVar<usize> = TVar::new(0);

        let var_clone = var.clone();

        let r1 = tokio::spawn(atomically(|tx| async move {
            let mut inner: usize = var_clone.read(&tx).await?;
            inner += 10;

            var_clone.write(inner, &tx).await?;

            Ok(())
        }));

        let result = r1.await.expect("Unable to join task").expect("Transaction failed");

        assert_eq!(result, 10);
    }

    #[tokio::test]
    async fn test_multiple_access() {
        let var: TVar<usize> = TVar::new(0);

        let var_1 = var.clone();
        let var_2 = var.clone();

        // this transaction reads a value, increment it and write the result back
        let r1 = tokio::spawn(atomically(|tx| async move {
            var_1.apply(|value| value + 10, &tx).await?;

            Ok(())
        }));

        // this transaction writes directly a value
        let r2 = tokio::spawn(atomically(|tx| async move {
            var_2.write(23, &tx).await?;

            Ok(())
        }));

        r1.await.expect("Unable to join task").expect("Transaction failed");
        r2.await.expect("Unable to join task").expect("Transaction failed");

        let result = var.read_atomic().await;

        assert_eq!(result, 33);
    }

    #[test]
    fn race_condition() {
        use std::sync::{Arc, Mutex};
        let runs = 100;

        for i in 0..runs {
            let v = Arc::new(Mutex::new(0));
            let v1 = v.clone();
            let v2 = v.clone();

            let r1 = std::thread::spawn(move || {
                let mut value = v1.lock().expect("could not get lock");
                *value = 20;
            });

            let r2 = std::thread::spawn(move || {
                let mut value = v2.lock().expect("could not get lock");
                *value = 10;
            });

            r1.join().expect("Failed to join");
            r2.join().expect("Failed to join");
            println!("run #{} = {}", i, 10 == *v.lock().expect("Could not get lock"));
        }
    }
}

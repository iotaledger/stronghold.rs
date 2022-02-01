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

use std::{future::Future, sync::Arc};

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
pub async fn atomically<W, T, P>(_program: P) -> Result<(), TransactionError>
where
    // F: Future,
    P: Fn(Arc<Transaction<W, T>>) -> W,
    T: Send + Sync + BoxedMemory,
    W: Future<Output = Result<(), TransactionError>>,
{
    Transaction::with_func(Arc::new(_program)).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn test_single_transaction() {
        let var: TVar<usize> = TVar::new(0);

        // let v1 = var.clone();
        // let v2 = var.clone();

        // let r1 = tokio::spawn(atomically(move |tx| {
        //     let v1 = v1.clone();
        //     let t1 = tx.clone();

        //     async move {
        //         v1.apply(|v| v + 10, &t1).await?;

        //         Ok(())
        //     }
        // }));

        // let r2 = tokio::spawn(atomically(move |tx| {
        //     let v1 = v2.clone();
        //     let t1 = tx.clone();

        //     async move {
        //         v1.apply(|v| v + 10, &t1).await?;

        //         Ok(())
        //     }
        // }));

        // let r2 = tokio::spawn(atomically(move |tx| modify(v2.clone(), tx.clone())));

        // let result = r1.await.expect("Unable to join task").expect("Transaction failed");

        // assert_eq!(result, 10);
    }

    #[tokio::test]
    async fn test_multiple_access() {
        let var: TVar<usize> = TVar::new(0);

        // let var_1 = var.clone();
        // let var_2 = var.clone();

        // // this transaction reads a value, increment it and write the result back
        // let r1 = tokio::spawn(atomically(move |tx| {
        //     let var_1 = var_1.clone();
        //     let tx = tx.clone();

        //     async move {
        //         var_1.apply(|value| value + 10, &tx).await?;

        //         Ok(())
        //     }
        // }));

        // // this transaction writes directly a value
        // let r2 = tokio::spawn(atomically(move |tx| {
        //     let var_2 = var_2.clone();
        //     let tx = tx.clone();

        //     async move {
        //         var_2.write(23, &tx).await?;

        //         Ok(())
        //     }
        // }));

        // r1.await.expect("Unable to join task").expect("Transaction failed");
        // r2.await.expect("Unable to join task").expect("Transaction failed");

        let result = var.read_atomic();
        assert!(result.is_ok());
        assert_eq!(result.expect("Failed to unwrap result"), 33);
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

    // remove this
    pub struct Container<F>
    where
        F: Future,
    {
        task: Arc<Mutex<Option<F>>>,
    }

    impl<F> Container<F>
    where
        F: Future,
    {
        fn new(task: F) -> Self {
            Self {
                task: Arc::new(Mutex::new(Some(task))),
            }
        }

        fn get(&self) -> F {
            let mut inner = self.task.lock().expect("");
            inner.take().unwrap()
        }
    }

    impl<F> Clone for Container<F>
    where
        F: Future,
    {
        fn clone(&self) -> Self {
            Self {
                task: self.task.clone(),
            }
        }
    }

    #[tokio::test]
    async fn test_inner_future() {
        let container = Container::new(async { println!("task run!") });

        let task = container.get();

        task.await;
    }
}

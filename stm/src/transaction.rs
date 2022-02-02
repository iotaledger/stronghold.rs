// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{boxedalloc::MemoryError, BoxedMemory, TLog, TVar, TransactionError};
use lazy_static::*;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

lazy_static! {
    pub(crate) static ref MANAGER: TransactionManager = TransactionManager::new();
}

/// Future generator
type FnFuture<T> = dyn Fn() -> Pin<Box<dyn Future<Output = T> + Unpin + Send>> + Send;

/// Keep track of running transaction
pub(crate) struct TransactionManager {
    tasks: Arc<
        Mutex<
            Vec<
                Box<
                    //
                    dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<(), TransactionError>>>> + Send,
                >,
            >,
        >,
    >,
}

impl TransactionManager {
    pub(crate) fn new() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn insert<F>(&self, task: Pin<Box<F>>) -> Result<(), TransactionError>
    where
        F: Future<Output = Result<(), TransactionError>> + Send + 'static,
    {
        let mut lock = self.tasks.lock().map_err(TransactionError::to_inner)?;
        lock.push(Box::new(move || task));

        Ok(())
    }

    pub(crate) fn size(&self) -> Result<usize, TransactionError> {
        Ok(self.tasks.lock().map_err(TransactionError::to_inner)?.len())
    }

    // pub(crate) async fn run_all(&self) -> Result<(), TransactionError> {
    //     let mut lock = self.tasks.lock().map_err(TransactionError::to_inner)?;

    //     for t in lock.iter() {
    //         t.await;
    //     }

    //     Ok(())
    // }
}

/// Defines a transaction strategy. Strategies vary
/// how transactions should be handled in case the commit
/// to memory fails.
pub enum Strategy {
    /// Aborts the transaction, so the user must try at an another point
    /// in time.
    Abort,

    /// Retries the transaction until it success. This is the default case,
    /// if no other `Strategy` is being provided
    Retry,
}

/// A transaction describes the intended operation on some shared memory
/// in concurrent / asynchronous setups. Each transaction writes a log off
/// changes for the shared memory, checking for conistence at the end
pub struct Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    strategy: Strategy,
    log: Arc<Mutex<BTreeMap<TVar<T>, TLog<T>>>>,
}

// impl<F, T> From<F> for Transaction<F, T>
// where
//     F: Future,
//     T: Send + Sync + BoxedMemory,
// {
//     fn from(task: F) -> Self {
//         Self {
//             strategy: Strategy::Retry,
//             log: Mutex::new(BTreeMap::new()),
//         }
//     }
// }

// impl<T> Future for Transaction<T>
// where
//     T: Send + Sync + BoxedMemory,
// {
//     type Output = Result<(), TransactionError>;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         todo!()
//     }
// }

impl<T> Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn new() -> Self {
        Self {
            strategy: Strategy::Retry,
            log: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn new_with_strategy(strategy: Strategy) -> Self {
        Self {
            strategy,
            log: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn with_func<P, W>(program: P) -> Result<(), TransactionError>
    where
        P: Fn(Arc<Self>) -> W,
        W: Future<Output = Result<(), TransactionError>> + Send + 'static,
    {
        Self::with_func_strategy(program, Strategy::Retry).await
    }

    pub async fn with_func_strategy<P, W>(program: P, strategy: Strategy) -> Result<(), TransactionError>
    where
        P: Fn(Arc<Self>) -> W,
        W: Future<Output = Result<(), TransactionError>> + Send + 'static,
    {
        // TODO: we need some protection, as nested transaction are not allowed

        let tx = Arc::new(Self::new_with_strategy(strategy));

        // we keep calling the transaction until it suceeds, or fails.
        // depending on the internally set strategy
        loop {
            let task = program(tx.clone());

            // TODO: this shall be removed
            MANAGER.insert(Box::pin(task)).expect("");

            // match task.await {
            //     Ok(_) => {
            //         if tx.commit().await.is_ok() {
            //             return Ok(());
            //         }
            //     }
            //     Err(e) => match tx.strategy {
            //         Strategy::Abort => {
            //             return Err(e);
            //         }
            //         Strategy::Retry => {
            //             if let Err(e) = tx.clear().await {
            //                 return Err(TransactionError::Inner(e.to_string()));
            //             }

            //             // TODO wait for a change in var
            //             tx.wait().await;
            //         }
            //     },
            // }
        }
    }

    /// Read a value from the transaction
    pub async fn read(&self, var: &TVar<T>) -> Result<T, TransactionError> {
        // let mut log = self.log.lock().map_err(TransactionError::to_inner)?;

        // // FIXME this will always create a new address
        // match log.entry(var.clone()) {
        //     Entry::Occupied(mut inner) => inner.get_mut().read().await,
        //     Entry::Vacant(entry) => {
        //         entry.insert(TLog::Read(var.read_atomic()?));
        //         var.read_atomic()
        //     }
        // }

        todo!()
    }

    /// Write value inside transaction
    pub async fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        // let mut log = self.log.lock().map_err(TransactionError::to_inner)?;

        // match log.entry(var.clone()) {
        //     Entry::Occupied(mut inner) => inner.get_mut().write(value).await,
        //     Entry::Vacant(entry) => {
        //         entry.insert(TLog::Write(value));
        //         Ok(())
        //     }
        // }

        todo!()
    }

    /// Applies a function on `var` and writes it back into `var`
    /// The function itself must be synchronous
    pub async fn apply<F>(&self, operation: F, var: &TVar<T>) -> Result<(), TransactionError>
    where
        F: FnOnce(T) -> T,
    {
        match self.read(var).await {
            Ok(inner) => self.write(operation(inner), var).await,
            Err(err) => Err(err),
        }
    }

    /// Writes all changes into the shared memory represented by [`TVar`]
    ///
    /// A commit compares all reads and writes with the actual value written to TVar
    async fn commit(&self) -> Result<(), TransactionError> {
        let txlog = std::mem::take(&mut *self.log.lock().map_err(TransactionError::to_inner).expect(""));

        for (var, log_entry) in txlog.iter() {
            match log_entry {
                TLog::Read(ref inner) => {
                    if !Arc::ptr_eq(&Arc::new(var.read_atomic()?), &Arc::new(inner.clone())) {
                        return Err(TransactionError::Failed("Inconsistent state.".to_string()));
                    }
                }
                TLog::Write(ref inner) => {}
                TLog::ReadWrite(ref original, ref inner) => {}
            }
        }

        // let mut writes = Vec::new();

        // for (ctrl, log_var) in entries.iter() {
        //     match log_var {
        //         TLog::Read(inner) => {
        //             // check if read value is equal to original value
        //             // TODO: "ptr comparison won't work here"
        //             // if !std::ptr::eq(
        //             //     &*ctrl.value.lock().map_err(TransactionError::to_inner)? as *const _ as *const T,
        //             //     inner as *const T,
        //             // ) {
        //             return Err(TransactionError::Failed("Read value is inconsistent".to_string()));
        //             // }
        //         }
        //         TLog::Write(inner) => {
        //             writes.push(ctrl);
        //         }
        //     }
        // }

        // // wake sleeping futures to continue
        // for c in writes {
        //     // c.wake().await.expect("");
        // }

        // //
        // Ok(())

        // todo!()

        Ok(())
    }

    /// Sets this transaction to sleep until changes have been made
    /// in another transaction. In a concurrent setup multiple futures
    /// are trying to read from a changed var. A valid change only occurs,
    /// when another transaction succeeds.
    ///
    /// The call to this function should make this transaction wait
    async fn wait(&self) {
        // TODO:

        todo!()
    }

    /// Safely clears the log, before starting a new transaction
    async fn clear(&self) -> Result<(), MemoryError> {
        // safely dealloc all log allocated memory
        // TODO: maybe this step is unecessary, because BoxedMemory automatically calls
        // zeroize on drop
        let mut log = self.log.lock().expect("msg");
        for (_, value) in log.iter_mut() {
            value.dealloc()?;
        }

        // clear the log
        log.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {}

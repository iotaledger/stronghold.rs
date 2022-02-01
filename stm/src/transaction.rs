// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{boxedalloc::MemoryError, ctrl::MemoryController, BoxedMemory, TLog, TVar, TransactionError};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

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

pub struct Transaction<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    strategy: Strategy,
    log: Mutex<BTreeMap<Arc<MemoryController<F, T>>, TLog<T>>>,
}

impl<F, T> Transaction<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    fn new() -> Self {
        Self {
            strategy: Strategy::Retry,
            log: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn new_with_strategy(strategy: Strategy) -> Self {
        Self {
            strategy,
            log: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn with_func<P, W>(program: Arc<P>) -> Result<(), TransactionError>
    where
        P: Fn(Arc<Self>) -> W,
        W: Future<Output = Result<(), TransactionError>>,
    {
        // TODO: we need some protection, as nested transaction are not allowed

        let tx = Arc::new(Self::new());

        // we keep calling the transaction until it suceeds, or fails.
        // depending on the internally set strategy
        loop {
            let task = program(tx.clone());

            match task.await {
                Ok(_) => {
                    if tx.commit().await.is_ok() {
                        return Ok(());
                    }
                }
                Err(e) => match tx.strategy {
                    Strategy::Abort => {
                        return Err(e);
                    }
                    Strategy::Retry => {
                        if let Err(e) = tx.clear().await {
                            return Err(TransactionError::Inner(e.to_string()));
                        }

                        // TODO wait for a change in var
                        // task = FutureBlocker::new(task).await?;
                    }
                },
            }
        }
    }

    pub async fn read(&self, _: &TVar<T>) -> Result<T, TransactionError> {
        let entries = self
            .log
            .lock()
            .map_err(|error| TransactionError::Inner(error.to_string()))?;

        // match entries.entry(var.ctrl()) {
        //     Entry::Occupied(entry) => entry.get().read().await,
        //     Entry::Vacant(vacant) => {
        //         let value = var.read_atomic()?;

        //         // HINT: this clones the memory
        //         vacant.insert(TLog::Read(value.clone()));

        //         Ok(value)
        //     }
        // }

        Err(TransactionError::Failed("Not implemented".to_string()))
    }

    pub async fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        let entries = self
            .log
            .lock()
            .map_err(|error| TransactionError::Inner(error.to_string()))?;

        // match entries.entry(var) {
        //     Entry::Occupied(entry) => entry.get().write(value).await,
        //     Entry::Vacant(vacant) => {
        //         let value = var.read_atomic()?;

        //         // HINT: this clones the memory
        //         vacant.insert(TLog::Write(value));

        //         Ok(())
        //     }
        // }

        Err(TransactionError::Failed("Not implemented".to_string()))
    }

    /// Writes all changes into the shared memory represented by [`TVar`]
    ///
    /// A commit compares all reads and writes
    async fn commit(&self) -> Result<(), TransactionError> {
        let entries = self
            .log
            .lock()
            .map_err(|error| TransactionError::Inner(error.to_string()))?;

        let mut writes = Vec::new();

        for (ctrl, log_var) in entries.iter() {
            match log_var {
                TLog::Read(inner) => {
                    // check if read value is equal to original value
                    // TODO: "ptr comparison won't work here"
                    if !std::ptr::eq(
                        &*ctrl.value.lock().map_err(TransactionError::to_inner)? as *const _ as *const T,
                        inner as *const T,
                    ) {
                        return Err(TransactionError::Failed("Read value is inconsistent".to_string()));
                    }
                }
                TLog::Write(inner) => {
                    writes.push(ctrl);
                }
            }
        }

        // wake sleeping futures to continue
        for c in writes {
            c.wake().await.expect("");
        }

        //
        Ok(())
    }

    /// Sets this transaction to sleep until changes have been made
    /// in another transaction. In a concurrent setup multiple futures
    /// are trying to read from a changed var. A valid change only occurs,
    /// when another transaction succeeds.
    async fn wait(&self) {
        // TODO:
        // -
    }

    /// Safely clears the log, before starting a new transaction
    async fn clear(&self) -> Result<(), MemoryError> {
        // safely dealloc all log allocated memory
        // TODO: maybe this step is unecessary, because BoxedMemory automatically calls
        // zeroize on drop
        let mut log = self.log.lock().expect("msg");
        for value in log.values_mut() {
            value.dealloc()?;
        }

        // clear the log
        log.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {}

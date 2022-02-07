// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ctrl::MemoryController, BoxedMemory, TLog, TVar, TransactionError};
// use lazy_static::*;
use log::*;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

/// Defines a transaction strategy. Strategies vary
/// how transactions should be handled in case the commit
/// to memory fails.
#[derive(Clone, Copy)]
pub enum Strategy {
    /// Aborts the transaction, so the user must try at an another point
    /// in time.
    Abort,

    /// Retries the transaction until it success. This is the default case,
    /// if no other `Strategy` is being provided
    Retry,
}

pub trait TransactionControl {
    /// Sets the current transaction to halt executing until
    /// the underlying variable has changed.
    fn wait(&self) -> Result<(), TransactionError>;

    /// Wakes the current transaction to continue
    fn wake(&self);
}

/// A transaction describes the intended operation on some shared memory
/// in concurrent / asynchronous setups. Each transaction writes a log off
/// changes for the shared memory, checking for conistence at the end
pub struct Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    strategy: Strategy,
    log: Arc<Mutex<BTreeMap<MemoryController<Self, T>, TLog<T>>>>,
    blocking: AtomicBool,
    program: Arc<Mutex<Box<dyn Fn(&Self) -> Result<(), TransactionError> + Send>>>,
}
impl<T> Clone for Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy,
            log: self.log.clone(),
            blocking: AtomicBool::new(self.blocking.load(Ordering::SeqCst)),
            program: self.program.clone(),
        }
    }
}

impl<T> Future for Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    type Output = Result<(), TransactionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.blocking.load(std::sync::atomic::Ordering::Acquire) {
            true => {
                info!("Executing transaction paused...");
                Poll::Pending
            }
            false => {
                info!("Running transaction");
                let program = &self.program.lock().unwrap();
                match program(&self) {
                    Ok(_) => {
                        info!("Committing transaction");
                        if self.commit().is_ok() {
                            info!("Transaction committed successfully");
                            return Poll::Ready(Ok(()));
                        }

                        info!("Running commit failed");

                        // inform waker, over re-check
                        ctx.waker().to_owned().wake();
                        Poll::Pending
                    }
                    Err(e) => match &self.strategy {
                        Strategy::Abort => Poll::Ready(Err(TransactionError::Aborted)),
                        Strategy::Retry => {
                            ctx.waker().to_owned().wake();

                            // clear
                            self.wait()?;
                            Poll::Pending
                        }
                    },
                }
            }
        }
        // we need to re-generate the task by closure
    }
}
impl<T> TransactionControl for Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    /// Sets this transaction to sleep until changes have been made
    /// in another transaction. In a concurrent setup multiple futures
    /// are trying to read from a changed var. A valid change only occurs,
    /// when another transaction succeeds.
    ///
    /// The call to this function should make this transaction wait
    fn wait(&self) -> Result<(), TransactionError> {
        let memctrl = MemoryController::new(5);
        memctrl.push(&Arc::new(self.clone()))?;

        self.blocking.store(true, Ordering::Release);

        Ok(())
    }

    fn wake(&self) {
        self.blocking.store(false, Ordering::Release);
    }
}

impl<T> Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub async fn with_func_strategy<P>(program: P, strategy: Strategy) -> Result<(), TransactionError>
    where
        P: Fn(&Self) -> Result<(), TransactionError> + Send + 'static,
    {
        // TODO: we need some protection, as nested transaction are not allowed
        // tx.await;

        info!("Creating transaction");

        // we keep calling the transaction until it suceeds, or fails.
        // depending on the internally set strategy
        Self {
            strategy,
            log: Arc::new(Mutex::new(BTreeMap::new())),
            blocking: AtomicBool::new(false),
            program: Arc::new(Mutex::new(Box::new(program))),
        }
        .await
    }

    /// Read a value from the transaction
    pub fn read(&self, var: &TVar<T>) -> Result<Arc<T>, TransactionError> {
        let key = match var.value.clone() {
            Some(key) => key,
            None => panic!(""),
        };

        match self.log.lock().map_err(TransactionError::to_inner)?.entry(key) {
            Entry::Occupied(mut inner) => return inner.get_mut().read(),
            Entry::Vacant(entry) => {
                entry.insert(TLog::Read(var.read()?));
                Ok(var.read().unwrap())
            }
        }
    }

    /// Write value inside transaction
    pub fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        info!("Write value into transaction: '{:?}'", value);
        match self
            .log
            .lock()
            .map_err(TransactionError::to_inner)?
            .entry(var.value.clone().unwrap())
        {
            Entry::Occupied(mut inner) => {
                info!("Write value into Log: '{:?}'", value);
                return inner.get_mut().write(value);
            }
            Entry::Vacant(entry) => {
                info!("Write value into new Log Entry: '{:?}'", value);
                entry.insert(TLog::Write(Arc::new(value)));
                Ok(())
            }
        }
    }

    /// Applies a function on `var` and writes it back into `var`
    /// The function itself must be synchronous
    pub fn apply<P>(&self, operation: P, var: &TVar<T>) -> Result<(), TransactionError>
    where
        P: FnOnce(Arc<T>) -> T,
    {
        match self.read(var) {
            Ok(inner) => self.write(operation(inner), var),
            Err(err) => Err(err),
        }
    }

    /// Writes all changes into the shared memory represented by [`TVar`]
    ///
    /// A commit compares all reads and writes with the actual value written to TVar
    fn commit(&self) -> Result<(), TransactionError> {
        let txlog = &self.log.lock().map_err(TransactionError::to_inner)?;

        // let mut reads = Vec::new();
        // let mut writes = Vec::new();
        let mut waking = Vec::new();

        info!("Validate transaction");
        for (var, log_entry) in txlog.iter() {
            info!("Check TLog Entry {:?}", log_entry);
            match log_entry {
                TLog::Write(ref inner) => {
                    info!("Check Write");
                    match var.value.write() {
                        Ok(mut lock) => {
                            // writes.push((lock, inner.clone()));
                            // TODO: shall we directly commit the value into memory, without checking
                            // first ?

                            *lock = inner.clone();
                            waking.push(var);
                        }
                        Err(err) => {
                            info!("Could not get Write lock");
                            return Err(TransactionError::to_inner(err));
                        }
                    }
                }
                TLog::Read(ref inner) => {
                    if let Ok(lock) = var.value.read() {
                        info!("Check Read");
                        if !Arc::ptr_eq(inner, &lock) {
                            return Err(TransactionError::InconsistentState);
                        }

                        info!("Store read lock");
                        // reads.push(lock);
                    }
                }

                TLog::ReadWrite(ref original, update) => {
                    info!("Check ReadWrite");
                    match var.value.write() {
                        Ok(mut lock) if Arc::ptr_eq(original, &lock) => {
                            // writes.push((lock, update.clone()));
                            *lock = update.clone();
                            waking.push(var);
                        }
                        _ => return Err(TransactionError::InconsistentState),
                    }
                }
            }
        }

        // info!("Commiting writes");
        // for (mut lock, var) in writes {
        //     *lock = var;
        // }

        info!("Wake all sleeping transaction");
        for w in waking {
            w.wake_all()?;
        }

        Ok(())
    }

    /// Safely clears the log, before starting a new transaction
    async fn clear(&mut self) -> Result<(), TransactionError> {
        // safely dealloc all log allocated memory
        // TODO: maybe this step is unecessary, because BoxedMemory automatically calls
        // zeroize on drop
        let mut log = self.log.lock().map_err(TransactionError::to_inner)?;

        for (_, value) in log.iter_mut() {
            match value {
                TLog::Read(inner) | TLog::Write(inner) | TLog::ReadWrite(_, inner) => {
                    // inner.dealloc();
                }
            };
        }

        // clear the log
        log.clear();

        Ok(())
    }
}

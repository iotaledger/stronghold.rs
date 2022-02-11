// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ctrl::MemoryController, types::structures::OrderedLog, LockedMemory, TLog, TVar, TransactionError};
use lazy_static::*;
use log::*;

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

lazy_static! {
    static ref TRANSACTION_ID: AtomicUsize = AtomicUsize::new(0);
}

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

    /// returns true, if current transaction is blocked
    fn is_blocked(&self) -> Result<bool, TransactionError>;

    /// Wakes the current transaction to continue
    fn wake(&self);
}

/// A transaction describes the intended operation on some shared memory
/// in concurrent / asynchronous setups. Each transaction writes a log off
/// changes for the shared memory, checking for conistence at the end
pub struct Transaction<T>
where
    T: Send + Sync + LockedMemory,
{
    strategy: Strategy,
    log: Arc<Mutex<OrderedLog<MemoryController<Self, T>, TLog<T>>>>,
    blocking: AtomicBool,
    program: Arc<Mutex<Box<dyn Fn(&Self) -> Result<(), TransactionError> + Send>>>,

    id: usize,
}
impl<T> Clone for Transaction<T>
where
    T: Send + Sync + LockedMemory,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy,
            log: self.log.clone(),
            blocking: AtomicBool::new(self.blocking.load(Ordering::SeqCst)),
            program: self.program.clone(),
            id: self.id,
        }
    }
}

impl<T> Future for Transaction<T>
where
    T: Send + Sync + LockedMemory,
{
    type Output = Result<(), TransactionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.is_blocked()? {
            true => {
                info!("tx [ {:04} ]: Execution paused", self.id);
                // inform waker, over re-check
                ctx.waker().to_owned().wake();
                Poll::Pending
            }
            false => {
                info!("tx [{:04}]:: Running", self.id);
                let program = &self.program.lock().unwrap();

                self.clear()?;

                match program(&self) {
                    Ok(_) => {
                        info!("tx [{:04}]:: Committing", self.id);

                        if self.commit().is_ok() {
                            info!("tx [{:04}]:: Successfully committed", self.id);

                            return Poll::Ready(Ok(()));
                        }

                        info!("tx [{:04}]:: Commit failed", self.id);

                        self.wait()?;

                        // inform waker, over re-check
                        ctx.waker().to_owned().wake();
                        Poll::Pending
                    }
                    Err(e) => match &self.strategy {
                        Strategy::Abort => Poll::Ready(Err(TransactionError::Aborted)),
                        Strategy::Retry => {
                            ctx.waker().to_owned().wake();

                            // clear
                            // self.clear()?;
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
    T: Send + Sync + LockedMemory,
{
    /// Sets this transaction to sleep until changes have been made
    /// in another transaction. In a concurrent setup multiple futures
    /// are trying to read from a changed var. A valid change only occurs,
    /// when another transaction succeeds.
    ///
    /// The call to this function should make this transaction wait
    fn wait(&self) -> Result<(), TransactionError> {
        // TODO: this code is dysfunctional. the memory controller
        // is not being inserted somewhere.
        // solution:
        // - need a dependency on tvar to add a wait
        // let memctrl = MemoryController::new(5);
        // memctrl.push(&Arc::new(self.clone()))?;

        let log = self.log.lock().map_err(TransactionError::to_inner)?;

        // TODO: removed, as we won't need it here
        // if let Some(entry) = log.keys().next() {
        //     entry.push(&Arc::new(self.clone()))?;
        //     self.blocking.store(true, Ordering::Release);
        // }

        Ok(())
    }

    fn is_blocked(&self) -> Result<bool, TransactionError> {
        info!("tx [{:04}]:: Checking transaction, if blocked", self.id);

        // check for blocking flag
        let flag = self.blocking.load(Ordering::Acquire);

        // check, if controller wants us to wake up
        let log = self.log.lock().map_err(TransactionError::to_inner)?;
        // let result = match log.next() {
        //     Some((ctrl, _)) => {
        //         // TODO: removed, because we have a different access to the underlying controller
        //         if let Ok(crate::ctrl::ControlResult::Wake) = ctrl.cleanup() {
        //             info!("tx [{:04}]:: MemoryControl: Signal wake", self.id);

        //             return Ok(false);
        //         }

        //         true | flag
        //     }
        //     None => flag,
        // };

        // Ok(result)
        todo!()
    }

    fn wake(&self) {
        self.clear().expect("Failed to clear");
        self.blocking.store(false, Ordering::Release);
    }
}

impl<T> Transaction<T>
where
    T: Send + Sync + LockedMemory,
{
    pub async fn with_strategy<P>(program: P, strategy: Strategy) -> Result<(), TransactionError>
    where
        P: Fn(&Self) -> Result<(), TransactionError> + Send + 'static,
    {
        // TODO: we need some protection, as nested transaction are not allowed
        // tx.await;

        info!("Creating Transaction");

        // we keep calling the transaction until it suceeds, or fails.
        // depending on the internally set strategy
        Self {
            strategy,
            log: Arc::new(Mutex::new(OrderedLog::new())),
            blocking: AtomicBool::new(false),
            program: Arc::new(Mutex::new(Box::new(program))),
            id: TRANSACTION_ID.fetch_add(1, Ordering::SeqCst),
        }
        .await
    }

    /// Read a value from the transaction
    /// TODO:
    /// This should return the value
    pub fn read(&self, var: &TVar<T>) -> Result<T, TransactionError> {
        let key = match var.value.clone() {
            Some(key) => key,
            None => panic!(""),
        };

        // match self.log.lock().map_err(TransactionError::to_inner)?.entry(key) {
        //     Entry::Occupied(mut inner) => return inner.get_mut().read(),
        //     Entry::Vacant(entry) => {
        //         entry.insert(TLog::Read((*var.read()?).clone()));
        //         Ok((*var.read()?).clone())
        //     }
        // }

        todo!()
    }

    /// Write value inside transaction
    pub fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        info!("tx [{:04}]:: Write value in transaction: ({:?}) ", self.id, value);

        // match self
        //     .log
        //     .lock()
        //     .map_err(TransactionError::to_inner)?
        //     .entry(var.value.clone().unwrap())
        // {
        //     Entry::Occupied(mut inner) => {
        //         info!("tx [{:04}]:: Write value into Log: '{:?}'", self.id, value);
        //         return inner.get_mut().write(value);
        //     }
        //     Entry::Vacant(entry) => {
        //         info!("tx [{:04}]:: Write value into new Log Entry: '{:?}'", self.id, value);
        //         entry.insert(TLog::Write(value));
        //         Ok(())
        //     }
        // }

        todo!()
    }

    /// Applies a function on `var` and writes it back into `var`
    /// The function itself must be synchronous
    pub fn apply<P>(&self, operation: P, var: &TVar<T>) -> Result<(), TransactionError>
    where
        P: FnOnce(T) -> T,
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
        let txlog = self.log.lock().map_err(TransactionError::to_inner)?;

        // let mut waking = Vec::new();

        info!("tx [{:04}]:: Validate", self.id);
        // for (var, log_entry) in *txlog {
        //     // info!("tx [{:04}]:: Check TLog Entry => ({:?})", self.id, log_entry);
        //     match log_entry {
        //         TLog::Write(ref inner) => {
        //             info!("tx [{:04}]:: Check Write => ({:?})", self.id, inner);

        //             // writes.push((lock, inner.clone()));
        //             // TODO: shall we directly commit the value into memory, without checking
        //             // first ?
        //             var.write(inner.clone());
        //             // *lock = inner.clone();
        //             waking.push(var);

        //             // TODO remove this, but store the value to be written in the vec
        //             // match var.value.write() {
        //             //     Ok(mut lock) => {
        //             //         // writes.push((lock, inner.clone()));
        //             //         // TODO: shall we directly commit the value into memory, without checking
        //             //         // first ?

        //             //         *lock = inner.clone();
        //             //         waking.push(var);
        //             //     }
        //             //     Err(err) => {
        //             //         info!("tx [{:04}]:: Could not get write lock", self.id);
        //             //         return Err(TransactionError::to_inner(err));
        //             //     }
        //             // }
        //         }
        //         TLog::Read(ref inner) => {
        //             if let Ok(value) = var.read() {
        //                 info!("tx [{:04}]:: Check Read => ({:?})", self.id, value);

        //                 if *inner != *value {
        //                     info!("tx [{:04}]:: Inconsistent State", self.id);
        //                     return Err(TransactionError::InconsistentState);
        //                 }
        //             }
        //         }

        //         TLog::ReadWrite(ref original, update) => {
        //             info!(
        //                 "tx [{:04}]:: Check ReadWrite => ({:?}), ({:?})",
        //                 self.id, original, update
        //             );

        //             match var.read() {
        //                 Ok(lock) if *original == *lock => {
        //                     // writes.push((lock, inner.clone()));
        //                     // TODO: shall we directly commit the value into memory, without checking
        //                     // first ?
        //                     var.write(update.clone());
        //                     // writes.push((lock, update.clone()));
        //                     // *lock = update.clone();
        //                     waking.push(var);
        //                 }
        //                 _ => return Err(TransactionError::InconsistentState),
        //             }
        //         }
        //     }
        // }

        // info!("tx [{:04}]:: Wake all sleeping transaction", self.id);
        // for w in waking {
        //     w.wake_all()?;
        //     w.cleanup()?;
        // }

        Ok(())
    }

    /// Safely clears the log, before starting a new transaction
    fn clear(&self) -> Result<(), TransactionError> {
        // safely dealloc all log allocated memory
        // TODO: maybe this step is unecessary, because BoxedMemory automatically calls
        // zeroize on drop
        let log = self.log.lock().map_err(TransactionError::to_inner)?;

        // for (_, value) in log.iter_mut() {
        //     match value {
        //         TLog::Read(inner) | TLog::Write(inner) | TLog::ReadWrite(_, inner) => {
        //             // inner.dealloc();
        //         }
        //     };
        // }

        // // clear the log
        // log.clear();

        // info!("tx [{:04}]:: Log size = {}", self.id, log.len());

        Ok(())
    }
}

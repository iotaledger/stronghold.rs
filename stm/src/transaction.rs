// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ctrl::MemoryController, BoxedMemory, TLog, TVar, TransactionError};
// use lazy_static::*;
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

// lazy_static! {
//     pub(crate) static ref MANAGER: TransactionManager = TransactionManager::new();
// }

// // /// Future generator
// // type FnFuture = dyn Fn() -> Pin<Box<dyn Future + Unpin + Send>> + Send;

// //  Keep track of running transaction
// pub(crate) struct TransactionManager {
//     tasks: Arc<Mutex<BTreeMap<usize, Transaction<BoxedMemory>>>>,
// }

// impl TransactionManager {
//     pub(crate) fn new() -> Self {
//         Self {
//             tasks: Arc::new(Mutex::new(BTreeMap::new())),
//         }
//     }
// }

//     pub(crate) fn insert<F>(&self, task: Pin<Box<F>>) -> Result<(), TransactionError>
//     where
//         F: Future + Send + 'static,
//     {
//         let mut lock = self.tasks.lock().map_err(TransactionError::to_inner)?;
//         lock.push(Box::new(move || Box::pin(task)));

//         Ok(())
//     }
// }

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

// pub trait Transactional {
//     type Error;
//     type Output;
//     type Type: Send + Sync + BoxedMemory;

//     ///
//     fn read(&self, var: &TVar<Self::Type>) -> Result<Self::Output, Self::Error>;

//     fn write(&self, value: Self::Type, var: &TVar<Self::Type>) -> Result<(), Self::Error>;
// }

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
            true => Poll::Pending,
            false => {
                let program = &self.program.lock().unwrap();
                match program(&self) {
                    Ok(_) => {
                        if self.commit().is_ok() {
                            return Poll::Ready(Ok(()));
                        }
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
    // fn new() -> Self {
    //     Self::new_with_strategy(Strategy::Retry)
    // }

    // pub(crate) fn new_with_strategy(strategy: Strategy) -> Self {
    //     Self {
    //         strategy,
    //         log: BTreeMap::new(),
    //         blocking: AtomicBool::new(false),
    //         program: Box::new(|tx| Ok(())),
    //     }
    // }

    // pub async fn with_func<P>(program: P) -> Result<(), TransactionError>
    // where
    //     P: Fn(&Self) -> Result<(), TransactionError> + 'static,
    // {
    //     Self::with_func_strategy(program, Strategy::Retry).await
    // }

    pub async fn with_func_strategy<P>(program: P, strategy: Strategy) -> Result<(), TransactionError>
    where
        P: Fn(&Self) -> Result<(), TransactionError> + Send + 'static,
    {
        // TODO: we need some protection, as nested transaction are not allowed
        // tx.await;

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
                entry.insert(TLog::Read(var.read_atomic()?));
                Ok(var.read_atomic().unwrap())
            }
        }
    }

    /// Write value inside transaction
    pub fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        match self
            .log
            .lock()
            .map_err(TransactionError::to_inner)?
            .entry(var.value.clone().unwrap())
        {
            Entry::Occupied(mut inner) => return inner.get_mut().write(value),
            Entry::Vacant(entry) => {
                entry.insert(TLog::Write(var.read_atomic()?));
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

        let mut reads = Vec::new();
        let mut waking = Vec::new();

        for (var, log_entry) in txlog.iter() {
            match log_entry {
                TLog::Write(ref inner) => match var.value.write() {
                    Ok(mut lock) => {
                        *lock = inner.clone();
                        waking.push(var);
                    }
                    Err(err) => return Err(TransactionError::to_inner(err)),
                },
                TLog::Read(ref inner) => {
                    if let Ok(lock) = var.value.read() {
                        if !Arc::ptr_eq(inner, &lock) {
                            return Err(TransactionError::InconsistentState);
                        }

                        reads.push(lock);
                    }
                }

                TLog::ReadWrite(ref original, update) => match var.value.write() {
                    Ok(mut lock) if Arc::ptr_eq(original, &lock) => {
                        *lock = update.clone();
                        waking.push(var);
                    }
                    _ => return Err(TransactionError::InconsistentState),
                },
            }
        }

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

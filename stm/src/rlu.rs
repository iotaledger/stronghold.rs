// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Software Transactional Memory: RLU Variant
//! ---
//! This module implements the read log update synchronization mechanism
//! to enable non-blocking concurrent reads and concurrent writes on
//! data.
//!
//! # Sources
//! - [notes](https://chaomai.github.io/2015/2015-09-26-notes-of-rlu/)
//! - [paper](https://people.csail.mit.edu/amatveev/RLU_SOSP15_paper.pdf)
//! - [reference impl](https://github.com/rlu-sync/rlu/blob/master/rlu.c)
//! - [rcu presentation](https://www.cs.unc.edu/~porter/courses/cse506/f11/slides/rcu.pdf)

#![allow(dead_code, unused_variables)]

use std::{
    cell::Cell,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::ThreadId,
    thread_local,
};

/// Virtual Type to use as return
pub trait ReturnType: Clone + Send + Sync + Sized + std::fmt::Debug {}

/// Global return type
pub type Result<T> = std::result::Result<T, TransactionError>;

/// Simplified atomic mutex
pub type ClonableMutex<T> = Arc<Mutex<T>>;

/// auto impl for return type
impl<T> ReturnType for T where T: Send + Sync + Clone + std::fmt::Debug {}

thread_local! {
    // pub static Guard: Cell<HashMap<Box<dyn Future<Output = Result<(), Box<dyn Error>>>>,bool>> = Cell::new(HashMap::new());
    pub static GUARD: Cell<bool> = Cell::new(false);
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction failed")]
    Failed,

    #[error("Transaction alread running")]
    InProgress,

    #[error("Inner error occured ({0})")]
    Inner(String),
}

/// a lightweight controller lock on concurrent readers
/// of [`TVar`]. The [`ReadLock`] takes care of decrementing
/// the number of readers on a [`TVar`].
pub struct ReadLock<T>
where
    T: ReturnType,
{
    var: TVar<T>,
    data: ClonableMutex<T>,
}

impl<T> ReadLock<T>
where
    T: ReturnType,
{
    pub fn read(&self) -> Result<T> {
        Ok(self
            .data
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?
            .clone())
    }
}

impl<T> Drop for ReadLock<T>
where
    T: ReturnType,
{
    fn drop(&mut self) {
        println!("Release read lock");
        self.var.release()
    }
}

pub enum WriteLock<T>
where
    T: ReturnType,
{
    Writer(ThreadId, Transaction<T>),
    None,
}

impl<T> Clone for WriteLock<T>
where
    T: ReturnType,
{
    fn clone(&self) -> Self {
        match self {
            WriteLock::Writer(id, tx) => WriteLock::Writer(*id, tx.clone()),
            WriteLock::None => WriteLock::None,
        }
    }
}

/// This is the global object for reading and
/// writing
pub struct TVar<T>
where
    T: ReturnType,
{
    g_clock: Arc<AtomicUsize>,
    data: Arc<Mutex<T>>,
    readers: Arc<AtomicUsize>,

    /// a map of all writers holding a lock on this object
    locked_by: Arc<Mutex<WriteLock<T>>>,
}

impl<T> TVar<T>
where
    T: ReturnType,
{
    pub fn new(data: T) -> Self {
        Self {
            g_clock: Arc::new(AtomicUsize::new(0)),
            data: Arc::new(Mutex::new(data)),
            readers: Arc::new(AtomicUsize::new(0)),

            locked_by: Arc::new(Mutex::new(WriteLock::None)),
        }
    }

    /// Read returns a [`ReadLock`] to read from
    /// the inner data. [`ReadLock`] keeps control over
    /// the number of readers inside the [`TVar<T>`]
    pub fn lock_read(&self) -> ReadLock<T> {
        // increment the number of readers
        self.acquire();

        // return a read lock
        ReadLock {
            var: self.clone(),
            data: self.data.clone(),
        }
    }

    pub fn lock_write(&self, id: ThreadId, tx: Transaction<T>) -> Result<()> {
        let mut locked_by = self
            .locked_by
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        *locked_by = WriteLock::Writer(id, tx);

        Ok(())
    }

    pub fn unlock_write(&self) -> Result<()> {
        let mut locked_by = self
            .locked_by
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        *locked_by = WriteLock::None;

        Ok(())
    }

    pub fn write(&self, var: T) -> Result<()> {
        let mut inner = self.data.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;

        *inner = var;

        Ok(())
    }

    /// waits until all readers have been released
    pub(crate) fn wait(&self) {
        println!("Wait for reader locks to release");
        while self.readers.load(Ordering::SeqCst) > 0 {
            std::thread::park()
        }

        println!("Reader lock has been released");
    }

    /// Acquires a reader, and increments the number of readers
    fn acquire(&self) {
        println!("Increment reader lock");
        self.readers.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the number of readers
    pub(crate) fn release(&self) {
        println!("Releasing reader lock.");
        self.readers.fetch_sub(1, Ordering::SeqCst);

        if self.readers.load(Ordering::SeqCst) == 0 {
            println!("Current thread {:?} can now continue", std::thread::current().id());
            std::thread::current().unpark();
        }
    }

    pub(crate) fn is_locked(&self) -> Result<WriteLock<T>> {
        let write_lock = self
            .locked_by
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        Ok(write_lock.clone())
    }

    /// Returns the global clock
    pub(crate) fn clock(&self) -> usize {
        self.g_clock.load(Ordering::SeqCst)
    }

    /// Updates the global clock
    pub(crate) fn clock_mut(&self, val: usize) {
        self.g_clock.store(val, Ordering::SeqCst)
    }

    /// Increments the globoal clock
    pub(crate) fn clock_inc(&self) {
        self.g_clock.fetch_add(1, Ordering::SeqCst);
    }
}

impl<T> Clone for TVar<T>
where
    T: ReturnType,
{
    fn clone(&self) -> Self {
        Self {
            g_clock: self.g_clock.clone(),
            data: self.data.clone(),
            readers: self.readers.clone(),
            locked_by: self.locked_by.clone(),
        }
    }
}

impl<T> From<T> for TVar<T>
where
    T: ReturnType,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

pub struct Transaction<T>
where
    T: ReturnType,
{
    /// identifier
    id: ThreadId,

    /// the local clock will be used to indicate the most recent
    /// state
    l_clock: Arc<AtomicUsize>,

    /// the write clock will be used to decide wether to
    /// read from the real state, or from the local log
    w_clock: Arc<AtomicUsize>,

    /// a list of recorded writes
    writes: Arc<Mutex<Vec<T>>>,
}

impl<T> Clone for Transaction<T>
where
    T: ReturnType,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            l_clock: self.l_clock.clone(),
            w_clock: self.w_clock.clone(),
            writes: self.writes.clone(),
        }
    }
}

impl<T> Transaction<T>
where
    T: ReturnType,
{
    pub fn with_func<F>(f: F) -> Result<()>
    where
        F: Fn(Self) -> Result<()>,
    {
        if GUARD.with(|inner| match inner.get() {
            true => true,
            false => {
                inner.set(true);
                false
            }
        }) {
            return Err(TransactionError::InProgress);
        }

        let tx = Self {
            id: std::thread::current().id(),
            l_clock: Arc::new(AtomicUsize::new(0)),
            w_clock: Arc::new(AtomicUsize::new(usize::MAX)),
            writes: Arc::new(Mutex::new(Vec::new())),
        };

        match f(tx) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn read(&self, var: &TVar<T>) -> Result<T> {
        self.l_clock_update(var);

        if let WriteLock::Writer(_, lock) = var.is_locked()? {
            if self.l_clock() >= lock.w_clock() {
                return lock.read_from_log();
            }
        }

        var.lock_read().read()
    }

    pub fn read_from_log(&self) -> Result<T> {
        let log = self.writes.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;

        // value is cloned again
        log.last()
            .cloned()
            .ok_or_else(|| TransactionError::Inner("No last element present".to_string()))
    }

    pub fn write(&self, value: T, var: &TVar<T>) -> Result<()> {
        // Write creates a copy of the value into the write log
        // and increments the write clock, which is newer than the global clock.
        // Older readers must be waited upon (quiescence loop: wait until all threads reading the value are finished),
        // before updating the values
        // while newer readers will read from the per thread write log
        self.l_clock_update(var);
        self.w_clock_update(var);

        // enter critical section
        println!("Set write lock");
        var.lock_write(std::thread::current().id(), self.clone())?;

        let mut writes = self.writes.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;

        // this should create a copy of read value
        (*writes).push(value);

        // this is higher than the g_clock
        self.w_clock_inc();
        var.clock_mut(self.w_clock());

        // wait for all reads
        var.wait();

        // commit
        println!("Committing writes");
        for val in writes.drain(0..) {
            var.write(val)?;
        }

        // leave critical section
        var.unlock_write()?;

        var.clock_mut(self.w_clock());

        // reset w_clock
        self.w_clock_mut(usize::MAX);

        Ok(())
    }

    pub(crate) fn l_clock(&self) -> usize {
        self.l_clock.load(Ordering::SeqCst)
    }

    pub(crate) fn l_clock_update(&self, var: &TVar<T>) {
        self.l_clock.store(var.clock(), Ordering::SeqCst);
    }

    pub(crate) fn w_clock(&self) -> usize {
        self.w_clock.load(Ordering::SeqCst)
    }

    pub(crate) fn w_clock_mut(&self, val: usize) {
        self.w_clock.store(val, Ordering::SeqCst)
    }

    pub(crate) fn w_clock_update(&self, var: &TVar<T>) {
        self.w_clock.store(var.clock(), Ordering::SeqCst);
    }

    pub(crate) fn w_clock_inc(&self) {
        self.w_clock.fetch_add(1, Ordering::SeqCst);
    }
}

impl<T> Drop for Transaction<T>
where
    T: ReturnType,
{
    fn drop(&mut self) {
        GUARD.with(|inner| inner.set(false));
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::collections::HashMap;

    fn rand_string() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(rand::thread_rng().gen_range(1..32))
            .map(char::from)
            .collect()
    }

    fn rand_usize() -> usize {
        rand::thread_rng().gen_range(0..255)
    }

    #[test]
    fn test_read_write() {
        let t: TVar<_> = HashMap::new().into();
        let num_threads = 2;
        let test_values: Vec<(TVar<_>, usize, String)> =
            std::iter::repeat_with(|| (t.clone(), rand_usize(), rand_string()))
                .take(num_threads)
                .collect();

        let mut handles = Vec::new();

        for (tcopy, id, value) in test_values.clone() {
            let handle = std::thread::spawn(move || {
                Transaction::with_func(|tx| {
                    let v = tx.read(&tcopy)?;

                    let mut h = v;
                    h.insert(id, value.clone());
                    tx.write(h, &tcopy)?;

                    Ok(())
                })
            });

            handles.push(handle);
        }

        for t_handle in handles.drain(0..) {
            if let Err(e) = t_handle.join().expect("Failed to join thread") {
                panic!("{}", e);
            }
        }

        let inner = t.lock_read().read().expect("Failed to access inner data");
        println!("inner: {:?}", inner);
        for (_, id, value) in test_values {
            assert!(inner.contains_key(&id));
        }
    }
}

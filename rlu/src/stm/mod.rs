// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Software Transactional Memory (STM)
//!
//! This module implements a variation of the TL2 algorithm described by Shavit et al. Access to shared
//! memory is being locked by a specialized bounded spin-lock with integrated versioning. The algorithm
//! differentiates between reading and writing transaction, while having some reading transaction performance
//! optimization in place.
pub mod error;
pub mod version;

pub use error::*;
pub use version::VersionLock;

use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
};

use self::version::VersionClock;

pub struct Transaction<T>
where
    T: Clone,
{
    /// A snapshot of the global version counter
    version: usize,

    /// The read set contains a reference to the locks of a transactable variable.
    /// This is thread local
    read: HashSet<TVar<T>>,

    /// The write set contains the transactable variable, the value to be written
    /// and the lock. This is thread local
    write: HashMap<TVar<T>, T>,
}

/// [`TVar`] encapsulates the original value to be modified,
/// keeps a local id, and writes copies of all changes into a log.
///
/// The local id is being defined by the global id being kept by the STM
// #[derive(Clone)]
pub struct TVar<T>
where
    T: Clone,
{
    /// This is the original value to be modified
    original: Arc<Mutex<T>>,

    /// This is a local version clock
    lock: VersionLock,

    version: VersionClock,
}

impl<T> Clone for TVar<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            original: self.original.clone(),
            lock: self.lock.clone(),
            version: self.version.copy(),
        }
    }
}

impl<T> Hash for TVar<T>
where
    T: Clone,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Due to API limitations, we cannot return the address of the object itself,
        // but has it in order to have some unique value to be stored inside the hashmap.
        let addr = std::ptr::addr_of!(self) as usize;
        addr.hash(state);
    }
}

impl<T> PartialEq for TVar<T>
where
    T: Clone,
{
    fn eq(&self, other: &Self) -> bool {
        let a = std::ptr::addr_of!(self) as usize;
        let b = std::ptr::addr_of!(other) as usize;

        a == b
    }
}

impl<T> Eq for TVar<T> where T: Clone {}

#[derive(Clone, Default)]
pub struct Stm {
    global: VersionClock,
}

impl Stm {
    /// This runs a transaction with the given context. The TL2 algorithm makes
    /// a distinction between write and read transactions. Calling this function
    /// will start a read-write transaction according to this algorithm:
    ///
    /// 1. Get Current Version
    ///    Sample the global version to detect changes to the transactable data
    /// 2. Speculative Execution
    ///
    ///    Try to run the transaction (eg. the function with the [`Transaction`] parameter). keep track of
    ///    the addresses loaded in the read set, and the address/value-to-be-written in a write set.
    ///    Check first, if a value has already been written in the write-set. return that value.
    /// 3. Lock the write-set
    /// 4. Validate the read-set
    /// 6. Commit changes to memory
    pub fn read_write<T, F>(&self, transaction: F) -> Result<(), TxError>
    where
        F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync,
    {
        // we required the latest global version to check for version consistency of writes

        loop {
            let mut tx = Transaction::<T>::new(self.global.version());
            match transaction(&mut tx) {
                Ok(_) => {
                    tx.lock_write_set()?;
                    let wv = self.global.increment()? + 1;

                    #[cfg(feature = "threaded")]
                    println!(
                        "ThreadId {:?} tries to write version {}",
                        std::thread::current().id(),
                        wv
                    );
                    tx.commit(wv)?;

                    break;
                }
                Err(e) => continue, // this can be augmented with a strategy
            }
        }

        Ok(())
    }

    /// This runs a transaction with the given context. The TL2 algorithm makes
    /// a distinction between write and read transactions. Calling this function
    /// will start a read transaction according to this algorithm:
    ///
    /// 1. Get Current Version
    ///    Sample the global version to detect changes to the transactable data
    /// 2. Speculative Execution
    ///    Try to run the transaction (eg. the function with the [`Transaction`] parameter). keep track of
    ///    the addresses loaded in the read set, and the address/value-to-be-written in a write set.
    ///    Check first, if a value has already been written in the write-set. return that value.
    pub fn read_only<T, F>(&self, transaction: F) -> Result<(), TxError>
    where
        F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync,
    {
        loop {
            let mut tx = Transaction::<T>::new(self.global.version());
            match transaction(&mut tx) {
                Ok(_) => {
                    break;
                }
                Err(e) => continue, // TODO: this can be augmented with a strategy
            }
        }
        Ok(())
    }

    /// This will create a new transactional variable [`TVar`].
    pub fn create<T>(&self, val: T) -> TVar<T>
    where
        T: Clone,
    {
        TVar {
            original: Arc::new(Mutex::new(val)),
            lock: VersionLock::default(),
            version: VersionClock::new(self.global.version()),
        }
    }
}

#[cfg(feature = "threaded")]
impl<T> Transaction<T>
where
    T: Clone,
{
    pub fn new(version: usize) -> Self {
        Self {
            version,
            read: HashSet::new(),
            write: HashMap::new(),
        }
    }

    /// This function loads the value from the transactional variable ([`TVar`]) and checks
    /// for version consistency. If the value, is present in a write set, this to-be-written value
    /// will be returned. In case there is a version mismatch, or the transactional variable is
    /// locked, an error will be returned and the [`Transaction`] will be retried.
    pub fn load(&mut self, tvar: &TVar<T>) -> Result<T, TxError> {
        self.read.insert(tvar.clone());

        if self.write.contains_key(tvar) {
            return Ok(self.write.get(tvar).unwrap().clone());
        }

        if tvar.lock.is_locked() {
            return Err(TxError::TransactionLocked);
        }

        let pre_version = tvar.lock.version();

        let data = tvar.original.lock().map_err(|e| TxError::LockPresent)?;

        let post_version = tvar.lock.version();

        let is_locked = tvar.lock.is_locked();
        let version_mismatch = pre_version != post_version;
        let stale_object = pre_version > self.version;

        match is_locked || version_mismatch || stale_object {
            true => Err(TxError::TransactionLocked),
            false => Ok((*data).clone()),
        }
    }

    /// this writes the value into the transactional log
    pub fn store(&mut self, tvar: &TVar<T>, value: T) {
        self.write.insert(tvar.clone(), value);
    }

    fn lock_write_set(&self) -> Result<(), TxError> {
        for tvar in self.write.keys() {
            if tvar.lock.try_lock().is_err() {
                return Err(TxError::Failed);
            }
        }

        Ok(())
    }

    /// Validates the read set
    fn validate(&self, wv: usize) -> Result<(), TxError> {
        let rv = self.version;
        if rv + 1 == wv {
            return Ok(());
        }

        for tvar in &self.read {
            if tvar.lock.version() >= rv {
                return Err(TxError::StaleObject);
            }

            if tvar.lock.is_locked() {
                return Err(TxError::TransactionLocked);
            }
        }

        Ok(())
    }

    /// Commits the write set to memory
    fn commit(&self, wv: usize) -> Result<(), TxError> {
        for (tvar, value) in &self.write {
            let mut guard = tvar.original.lock().map_err(|_| TxError::LockPresent)?;
            *guard = value.clone();

            drop(guard);

            tvar.lock.release_set(wv)
        }

        Ok(())
    }
}

impl<T> TVar<T>
where
    T: Clone,
{
    pub fn get(&self) -> Result<T, TxError> {
        Ok((*self.original.lock().map_err(|_| TxError::LockPresent)?).clone())
    }
}

unsafe impl<T> Send for TVar<T> where T: Clone + Send + Sync {}

unsafe impl<T> Sync for TVar<T> where T: Clone + Send + Sync {}

#[cfg(test)]
mod tests {
    use crate::stm::Transaction;

    use super::Stm;

    /// Some testing struct
    #[derive(Default, Clone, PartialEq, Eq, Debug)]
    struct Complex {
        id: usize,
        reference: String,
    }

    #[test]
    fn test_stm_basic() {
        let stm = Stm::default();

        let bank_alice = stm.create(10usize);
        let bank_bob = stm.create(100);

        let ba = bank_alice.clone();
        let bb = bank_bob.clone();

        let result = stm.read_write(move |tx: &mut Transaction<_>| {
            let mut amt_bob = tx.load(&bb)?;

            let amt_alice = amt_bob - 20;
            amt_bob -= 20;

            tx.store(&ba, amt_alice);
            tx.store(&bb, amt_bob);

            Ok(())
        });

        assert!(result.is_ok(), "Transaction failed");

        assert_eq!(bank_alice.get(), Ok(80));
        assert_eq!(bank_bob.get(), Ok(80));
    }

    #[test]
    #[cfg(feature = "threaded")]
    fn test_stm_threaded() {
        use crate::stm::TVar;
        use rand::Rng;
        use std::collections::HashSet;
        use threadpool::ThreadPool;

        let mut rng = rand::thread_rng();
        let stm = Stm::default();
        let entries: usize = rng.gen_range(0..100);

        let expected: HashSet<String> = (0..entries)
            .map(|_| rng.gen())
            .map(|e: usize| format!("{:016}", e))
            .collect();

        let set: TVar<HashSet<String>> = stm.create(HashSet::new());
        let pool = ThreadPool::new(8);

        for value in &expected {
            let stm_a = stm.clone();
            let set_a = set.clone();
            let value = value.clone();
            pool.execute(move || {
                let result = stm_a.read_write(move |tx: &mut Transaction<_>| {
                    let mut inner = tx.load(&set_a)?;

                    inner.insert(value.clone());
                    tx.store(&set_a, inner);

                    Ok(())
                });
                assert!(result.is_ok(), "Failed to run transaction");
            });
        }

        // synchronized all running worker threads
        pool.join();

        let result = set.get();
        assert!(result.is_ok());

        let actual = result.unwrap();
        assert_eq!(actual, expected, "Actual HashSet is not equal to expected HashSet");
    }

    #[test]
    #[cfg(feature = "async")]
    fn test_stm_async() {}
}

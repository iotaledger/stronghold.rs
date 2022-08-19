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
use self::version::VersionClock;
pub use error::*;
use log::*;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicIsize},
        Arc,
        Mutex, MutexGuard,
    },
};
// use no_deadlocks::{Mutex, MutexGuard};

pub use version::VersionLock;

pub struct Transaction<T>
where
    T: Clone,
{
    /// Transaction id
    id: usize,

    /// A snapshot of the global version counter
    version: usize,

    /// The read set contains a reference to the locks of a transactable variable.
    /// This is thread local
    read: HashSet<TVar<T>>,

    /// The write set contains the transactable variable, the value to be written
    /// and the lock. This is thread local
    write: HashMap<TVar<T>, T>,
}

/// A Strategy to handle transaction failures. Two options are possible:
/// - Retry: This will endlessly retry a transaction until it succeeds
/// - Abort: This will abort a transaction, if it fails
#[derive(Debug)]
pub enum Strategy {
    /// This will retry the transaction until it succeeds
    Retry,

    /// This will abort the transaction, if it fails
    Abort,
}

/// This enum is for internal use only. It indicates either if
/// it's the `Same` thread locking a [`crate::stm::TVar`], a `Foreign` thread or if
/// `None` is actually present.
#[derive(Debug)]
pub(crate) enum ThreadLockState {
    Same,
    Foreign,
    None,
}

#[cfg(feature = "threaded")]
// #[derive(Debug)]
struct Pair<T>
where
    T: Clone,
{
    value: Mutex<T>,
    id: Arc<AtomicIsize>,
}

impl<T: Clone> Debug for Pair<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "toto")
    }
}

#[cfg(feature = "threaded")]
impl<T> Pair<T>
where
    T: Clone,
{
    pub(crate) fn new(value: T) -> Self {
        Self {
            value: Mutex::new(value),
            id: Arc::new(AtomicIsize::new(-1)),
        }
    }

    pub(crate) fn lock(&self, transaction_id: usize) -> Result<PairGuard<'_, T>, TxError> {
        let value_guard = self.value.lock().map_err(|_| TxError::LockPresent)?;

        self.id
            .store(transaction_id as isize, std::sync::atomic::Ordering::SeqCst);

        Ok(PairGuard::new(value_guard, self.id.clone()))
    }
}

#[cfg(feature = "threaded")]
pub struct PairGuard<'a, T>
where
    T: Clone,
{
    inner: MutexGuard<'a, T>,
    id: Arc<AtomicIsize>,
}

#[cfg(feature = "threaded")]
impl<'a, T> PairGuard<'a, T>
where
    T: Clone,
{
    pub(crate) fn new(inner: MutexGuard<'a, T>, id: Arc<AtomicIsize>) -> Self {
        Self { inner, id }
    }
}

#[cfg(feature = "threaded")]
impl<'a, T> Drop for PairGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        self.id.store(-1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// [`TVar`] encapsulates the original value to be modified,
/// keeps a local id, and writes copies of all changes into a log.
///
/// The local id is being defined by the global id being kept by the STM
#[derive(Clone, Debug)]
pub struct TVar<T>
where
    T: Clone,
{
    #[cfg(feature = "threaded")]
    /// This is the original value to be modified
    // Contains <Mutex<T>, Arc<AtomicIsize>>,
    // second field contains the transaction id
    original: Arc<Pair<T>>,

    /// This is a local version clock
    lock: VersionLock,
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

impl<T> TVar<T>
where
    T: Clone,
{
    pub fn get(&self) -> Result<T, TxError> {
        Ok((*self.original.value.lock().map_err(|_| TxError::LockPresent)?).clone())
    }
}

#[cfg(feature = "threaded")]
impl<T> TVar<T>
where
    T: Clone,
{
    pub(crate) fn is_locked_by(&self, transaction_id: usize) -> ThreadLockState {
        let id = self.original.id.load(std::sync::atomic::Ordering::SeqCst);

        if id == -1 {
            return ThreadLockState::None;
        }
        if id == transaction_id as isize {
            return ThreadLockState::Same;
        }

        ThreadLockState::Foreign
    }

    pub(crate) fn locked_by(&self) -> Result<isize, TxError> {
        Ok(self.original.id.load(std::sync::atomic::Ordering::SeqCst))
    }

    pub(crate) fn lock(&self, transaction_id: usize) -> Result<(), TxError> {
        self.original
            .id
            .store(transaction_id as isize, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    pub(crate) fn unlock(&self) -> Result<(), TxError> {
        self.original.id.store(-1, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Stm {
    global: VersionClock,

    transaction_ids: VersionClock,
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
    pub fn read_write<T, F>(&self, transaction: F, strategy: Strategy) -> Result<(), TxError>
    where
        F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync + Debug,
    {
        // increment per thread
        let id = self.transaction_ids.increment()?;

        // we require the latest global version to check for version consistency of writes
        loop {
            let mut tx = Transaction::<T>::new(self.global.version(), id);
            info!(
                "TRANSACTION({:?}): START. GLOBAL VERSION ({:04})",
                tx.id,
                self.global.version()
            );
            match transaction(&mut tx) {
                Ok(_) => {
                    if tx.lock_write_set().is_err() {
                        info!("TRANSACTION({:?}): LOCK WRITE SET FAILED", tx.id);
                        continue;
                    }
                    let wv = self.global.increment()?;
                    info!("TRANSACTION({:?}): INCREMENT GLOBAL VERSION: ({})", id, wv);

                    if tx.validate(wv).is_err() {
                        info!("TRANSACTION({:?}): VALIDATING READ SET FAILED", tx.id);
                        continue;
                    }

                    if tx.commit(wv).is_err() {
                        info!("TRANSACTION({:?}): COMMITTING VALUE FAILED", tx.id);
                        continue;
                    };

                    break;
                }
                Err(e) => {
                    info!("TRANSACTION({:?}): FAILED. RETRYING", tx.id);
                    // std::thread::sleep(Duration::from_millis(1000));
                    match strategy {
                        Strategy::Abort => return Err(TxError::Failed),
                        Strategy::Retry => continue,
                    }
                } // this can be augmented with a strategy
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
        T: Clone + Send + Sync + Debug,
    {
        loop {
            let mut tx = Transaction::<T>::new(self.global.version(), self.transaction_ids.increment()?);
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
            original: Arc::new(Pair::new(val)),
            lock: VersionLock::new(self.global.version()),
        }
    }
}

#[cfg(feature = "threaded")]
impl<T> Transaction<T>
where
    T: Clone + Debug,
{
    pub fn new(version: usize, id: usize) -> Self {
        Self {
            version,
            read: HashSet::new(),
            write: HashMap::new(),
            id,
        }
    }

    /// This function loads the value from the transactional variable ([`TVar`]) and checks
    /// for version consistency. If the value is present in a write set, this to-be-written value
    /// will be returned. In case there is a version mismatch, or the transactional variable is
    /// locked, an error will be returned and the [`Transaction`] will be retried.
    pub fn load(&mut self, tvar: &TVar<T>) -> Result<T, TxError> {
        self.read.insert(tvar.clone());

        if self.write.contains_key(tvar) {
            return Ok(self.write.get(tvar).unwrap().clone());
        }

        if tvar.lock.is_locked() {
            match tvar.is_locked_by(self.id) {
                ThreadLockState::Same | ThreadLockState::None => {
                    tvar.lock.unlock()?;
                }
                ThreadLockState::Foreign => {
                    info!(
                        "LOAD({:?}): PRECHECK TRANSACTION LOCKED BY ({:?})",
                        self.id,
                        tvar.locked_by()
                    );
                    return Err(TxError::TransactionLocked);
                }
            }
        }

        let pre_version = tvar.lock.version();

        let data = tvar.original.value.lock().map_err(|e| TxError::LockPresent)?;
        // info!("LOAD({:?}): TVAR CONTENTS ({:?})", self.id, data);
        let post_version = tvar.lock.version();

        let is_locked = tvar.lock.is_locked();
        let version_mismatch = pre_version != post_version;
        let stale_object = pre_version > self.version;

        match is_locked || version_mismatch || stale_object {
            true => {
                info!(
                    "LOAD({:?}): VERSION MISMATCH ({}), STALE OBJECT ({}), PRE_VERSION ({}), TRANSACTION_VERSION ({})",
                    self.id, version_mismatch, stale_object, pre_version, self.version
                );
                Err(TxError::VersionMismatch)
            }
            false => Ok((*data).clone()),
        }
    }

    /// this writes the value into the transactional log
    pub fn store(&mut self, tvar: &TVar<T>, value: T) -> Result<(), TxError> {
        self.write.insert(tvar.clone(), value);

        Ok(())
    }

    #[inline(always)]
    fn lock_write_set(&self) -> Result<(), TxError> {
        // TODO do we need this as atomic?
        let fail_lock_write = AtomicBool::new(false);

        for tvar in self.write.keys() {
            info!("TRANSACTION({:?}): WRITE LOCK", self.id);

            //TODO current implementation of try_lock cannot fail
            if tvar.lock.try_lock().is_err() {
                info!("LOCK WRITE SET({:?}): TRANSACTION LOCKED.", self.id);
                fail_lock_write.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }

            match tvar.is_locked_by(self.id) {
                ThreadLockState::Foreign => {
                    fail_lock_write.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                _ => {
                    info!(
                        "TRANSACTION({:?}): LOCK HELD BY US OR NONE ({:?})",
                        self.id,
                        tvar.is_locked_by(self.id)
                    );
                }
            }

            // lock to thread id
            tvar.lock(self.id)?;
        }

        if fail_lock_write.load(std::sync::atomic::Ordering::SeqCst) {
            for tvar in self.write.keys() {
                // TODO shouldn't we only unlock tvar locked by our own thread id?
                tvar.lock.unlock()?;
            }

            info!("LOCK WRITE SET({:?}):  RESETTING LOCKS", self.id);
            return Err(TxError::Failed);
        }

        info!("TRANSACTION({:?}): WRITE LOCK SUCCESS", self.id);

        Ok(())
    }

    /// Validates the read set
    #[inline(always)]
    fn validate(&self, wv: usize) -> Result<(), TxError> {
        let rv = self.version;
        if rv + 1 == wv {
            return Ok(());
        }

        for tvar in &self.read {
            // TODO paper says > but => gives better result here
            if tvar.lock.version() > rv {
            // if tvar.lock.version() => rv {
                info!(
                    "VALIDATE({:?}): OBJECT STALE. READ_VERSION ({}), OBJECT VERSION ({})",
                    self.id,
                    rv,
                    tvar.lock.version()
                );

                return Err(TxError::StaleObject);
            }

            match tvar.is_locked_by(self.id) {
                ThreadLockState::Same | ThreadLockState::None => {
                    info!(
                        "VALIDATE({:?}): TRANSACTION LOCKED BY US OR NONE. CLEARING LOCKS",
                        self.id
                    );
                    tvar.lock.unlock()?;

                    continue;
                }
                _ => return Err(TxError::TransactionLocked),
            }
        }

        Ok(())
    }

    /// Commits the write set to memory
    #[inline(always)]
    fn commit(&self, wv: usize) -> Result<(), TxError> {
        for (tvar, value) in &self.write {
            info!("COMMIT({:?}): BEGIN VERSION ({:04})", self.id, wv);
            let mut guard = tvar.original.value.lock().map_err(|_| TxError::LockPresent)?;
            *guard = value.clone();

            drop(guard);

            info!(
                "COMMIT({:?}): UPDATED TRANSACTIONAL VARIABLE TO VERSION VERSION ({}) ",
                self.id, wv
            );
            tvar.lock.release_set(wv)?;
            info!("COMMIT({:?}): VARIABLE UNLOCKED", self.id);

            info!(
                "COMMIT({:?}): END UNLOCKED VERSION ({:04}). IS LOCKED? ({}). THREAD_LOCK ({:?})",
                self.id,
                tvar.lock.version(),
                tvar.lock.is_locked(),
                tvar.locked_by()?,
            );
        }

        // unlock all tvars
        for tvar in self.write.keys() {
            if let Err(e) = tvar.unlock() {
                info!("ERROR UNLOCKING TVAR AFTER COMMIT. ({:?})", e)
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Stm;
    use crate::stm::{TVar, Transaction};
    use std::collections::HashSet;
    use threadpool::ThreadPool;

    #[allow(unused_imports)]
    use log::*;

    #[test]
    fn test_stm_basic() {
        let stm = Stm::default();

        let bank_alice = stm.create(10usize);
        let bank_bob = stm.create(100);

        let ba = bank_alice.clone();
        let bb = bank_bob.clone();

        let result = stm.read_write(
            move |tx: &mut Transaction<_>| {
                let mut amt_bob = tx.load(&bb)?;

                let amt_alice = amt_bob - 20;
                amt_bob -= 20;

                tx.store(&ba, amt_alice)?;
                tx.store(&bb, amt_bob)?;

                Ok(())
            },
            crate::stm::Strategy::Retry,
        );

        assert!(result.is_ok(), "Transaction failed");

        assert_eq!(bank_alice.get(), Ok(80));
        assert_eq!(bank_bob.get(), Ok(80));
    }

    #[test]
    // #[cfg(feature = "threaded")]
    fn run_stm_threaded() {
        use rand::{distributions::Bernoulli, prelude::Distribution};

        #[cfg(feature = "verbose")]
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .init();

        let stm = Stm::default();
        let entries: usize = 10;

        // bernoulli distribution over reads vs read/write transactions
        let distribution = Bernoulli::new(0.7).unwrap();

        let mut expected: HashSet<String> = (0..entries).map(|e: usize| format!("{:04}", e)).collect();

        let set: TVar<HashSet<String>> = stm.create(HashSet::new());
        let pool = ThreadPool::new(8);

        let mut removal = HashSet::new();

        for value in expected.iter() {
            let stm_a = stm.clone();
            let set_a = set.clone();
            let value = value.clone();

            let is_readonly = distribution.sample(&mut rand::thread_rng());
            // TODO remove, only used for debugging
            let is_readonly = false;

            // We store the value that won't be written
            if is_readonly {
                removal.insert(value.clone());
            }

            pool.execute(move || {
                let result = {
                    match is_readonly {
                        false => stm_a.read_write(
                            move |tx: &mut Transaction<_>| {
                                let mut inner = tx.load(&set_a)?;
                                info!(
                                    "LOAD DONE({:?}): read set ({:?}) ",
                                    tx.id, inner
                                );

                                inner.insert(value.clone());
                                tx.store(&set_a, inner.clone())?;

                                info!(
                                    "STORED in WRITE SET({:?}): new set ({:?}) ",
                                    tx.id, inner
                                );



                                Ok(())
                            },
                            crate::stm::Strategy::Retry,
                        ),

                        true => stm_a.read_only(move |tx: &mut Transaction<_>| {
                            let inner = tx.load(&set_a);
                            Ok(())
                        }),
                    }
                };

                // assert!(result.is_ok(), "Failed to run transaction");
            });
        }

        // synchronized all running worker threads
        pool.join();

        for value in removal.iter() {
            expected.remove(value);
        }

        let result = set.get();
        assert!(result.is_ok());


        let actual = result.unwrap();
        // assert!(false);

        assert!(
            expected == actual,
            "Actual collection is not equal to expected collection: missing {:?}",
            expected.symmetric_difference(&actual)
        );
    }

    #[test]
    #[cfg(feature = "async")]
    fn test_stm_async() {}
}

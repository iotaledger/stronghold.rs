// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

/// In the following we describe the PS version of the TL2 algorithm although
/// most of the details carry through verbatim for PO as well.
///
/// We maintain thread local read- and write-sets as linked lists. Each read-set entries contains the address
/// of the lock that “covers” the variable being read, and unlike former algorithms,
/// does not need to contain the observed version number of the lock.
///
/// The write-set entries contain the address of the variable, the value to be written to the variable,
/// and the address of its associated lock. In many cases the lock and location
/// address are related and so we need to keep only one of them in the read-set. The
/// write-set is kept in chronological order to avoid write-after-write hazards.
#[derive(Clone)]
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
#[derive(Clone)]
pub struct TVar<T>
where
    T: Clone,
{
    /// This is the original value to be modified
    original: Arc<Mutex<T>>,

    /// This is a local version clock
    local: VersionLock,
}

impl<T> Hash for TVar<T>
where
    T: Clone,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        todo!()
    }
}

impl<T> PartialEq for TVar<T>
where
    T: Clone,
{
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl<T> Eq for TVar<T> where T: Clone {}

#[derive(Clone, Default)]
pub struct Stm {
    global: VersionClock,
}

impl Stm {
    /// This runs a transaction with the given context. The TL2 algorithm makes
    /// a distinction between write and read transactions. A write transaction does the following
    /// steps:
    /// 1. sample the global version to detect changes to the transactable data
    /// 2. try to run the transaction (eg. the function with the [`Transaction`] parameter). keep track of
    ///    the addresses loaded in the read set, and the address/value-to-be-written in a write set.
    ///    Check first, if a value has already been written in the write-set. return that value.
    pub fn atomically<T, F>(&self, transaction: F) -> Result<(), TxError>
    where
        F: Fn(Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync,
    {
        // we required the latest global version to check for version consistency of writes

        loop {
            match transaction(Transaction::new(self.global.version())) {
                Ok(_) => break,
                Err(e) => continue, // this can be augmented with a strategy
            }
        }

        Ok(())
    }

    pub fn create<T>(&self, val: T) -> TVar<T>
    where
        T: Clone,
    {
        TVar {
            original: Arc::new(Mutex::new(val)),
            local: VersionLock::new(self.global.version()),
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

    /// this loads a transactional variable from the log
    /// and returns a clone of the value
    pub fn load(&self, tvar: &TVar<T>) -> Result<T, TxError> {
        let pre_version = self.version;

        if tvar.local.is_locked() {
            return Err(TxError::TransactionLocked);
        }

        let data = self.read.get(tvar);
        let post_version = tvar.local.version();

        // Ok(data)
        todo!()
    }

    /// this writes the value into the transactional log
    pub fn store(&self, tvar: &TVar<T>, value: T) -> Result<(), TxError> {
        // let mut guard = tvar.write.lock().expect("");
        // *guard = Some(value);

        // tvar.local.release();

        Ok(())
    }
}

impl<T> TVar<T>
where
    T: Clone + Send + Sync,
{
    pub fn version(&self) -> usize {
        self.local.version()
    }

    pub fn read(&self) -> T {
        self.original.lock().expect("").clone()
    }
}

unsafe impl<T> Send for TVar<T> where T: Clone + Send + Sync {}
unsafe impl<T> Sync for TVar<T> where T: Clone + Send + Sync {}

#[cfg(test)]
mod tests {
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

        let result = stm.atomically(move |transaction| {
            let mut amt_bob = transaction.load(&bank_bob)?;

            let amt_alice = amt_bob - 20;
            amt_bob -= 20;

            transaction.store(&bank_alice, amt_alice)?;
            transaction.store(&bank_bob, amt_bob)?;

            Ok(())
        });

        assert!(result.is_ok(), "Transaction failed")
    }
}

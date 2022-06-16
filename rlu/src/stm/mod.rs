// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod error;
pub mod vlock;

pub use error::*;
pub use vlock::VersionLock;

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone)]
pub struct Stm<T>
where
    T: Clone,
{
    log: Arc<Mutex<HashMap<usize, BTreeMap<Operation, T>>>>,

    /// this is a global clock
    global: Arc<AtomicUsize>,
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
    local: Arc<AtomicUsize>,

    reads: Arc<Mutex<BTreeMap<usize, T>>>,

    writes: Arc<Mutex<BTreeMap<usize, T>>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    Read,
    Write,
    ReadWrite,
}

pub enum Strategy {
    Retry,
    Abort,
}

impl<T> Stm<T>
where
    T: Clone,
{
    pub fn with_strategy<F>(&self, transaction: F, strategy: Strategy) -> Result<(), TxError>
    where
        F: FnOnce(Self) -> Result<(), TxError>,
    {
        let tx = Stm::new();
        transaction(tx)?;

        loop {
            match self.verify() {
                Ok(_) => self.commit(),
                Err(e) => match strategy {
                    Strategy::Retry => {
                        continue;
                    }
                    Strategy::Abort => break,
                },
            }
        }

        Ok(())
    }

    pub fn create(&self, val: T) -> TVar<T> {
        TVar {
            original: Arc::new(Mutex::new(val)),
            local: Arc::new(AtomicUsize::new(self.next_id())),

            // read set
            reads: Arc::new(Mutex::new(BTreeMap::new())),

            // write set
            writes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn next_id(&self) -> usize {
        self.global.fetch_add(1, Ordering::SeqCst)
    }
}

#[cfg(feature = "threaded")]
impl<T> Stm<T>
where
    T: Clone,
{
    pub fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(HashMap::new())),
            global: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// this reads a transactional variable from the log
    /// and returns a clone of the value
    pub fn read(&self, tvar: &TVar<T>) -> Result<T, TxError> {
        let version_global = self.global.load(Ordering::SeqCst);
        let version_local = tvar.local.load(Ordering::SeqCst);

        let mut log = self.log.lock().expect("Failed to unlock internal log");
        let tree = log.get_mut(&tvar.id()).unwrap();
        let read = tree.values().next_back().unwrap().clone();
        tree.insert(Operation::Read, read.clone());

        Ok(read)
    }

    /// this writes the value into the transactional log
    pub fn write(&self, tvar: &TVar<T>, value: T) -> Result<(), TxError> {
        let mut log = self.log.lock().expect("Failed to unlock internal log");
        let tree = log.get_mut(&tvar.id()).unwrap();

        tree.insert(Operation::Write, value);

        Ok(())
    }

    fn verify(&self) -> Result<(), TxError> {
        Ok(())
    }

    fn commit(&self) {}

    fn retry(&self) {}
}

impl<T> TVar<T>
where
    T: Clone,
{
    pub fn id(&self) -> usize {
        self.local.load(Ordering::SeqCst)
    }

    pub fn read(&self) -> T {
        self.original.lock().expect("").clone()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Some testing struct
    #[derive(Default, Clone, PartialEq, Eq, Debug)]
    struct Complex {
        id: usize,
        reference: String,
    }

    #[test]
    fn test_stm_basic() {
        let stm = Stm::new();

        let tvar = stm.create(Complex::default());

        let ttvar = tvar.clone();

        assert!(stm
            .with_strategy(
                move |tx: Stm<Complex>| {
                    let mut state_a = tx.read(&ttvar)?;
                    state_a.id = 999;
                    tx.write(&ttvar, state_a)?;

                    Ok(())
                },
                Strategy::Retry
            )
            .is_ok());

        let actual = tvar.read();
        let expected = Complex {
            id: 999,
            reference: "".to_string(),
        };

        assert_eq!(actual, expected);
    }
}

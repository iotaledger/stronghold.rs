// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::simple_stm::{error::TxError, transaction::Transaction, tvar::TVar};
use log::*;
use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

// TODO:
// - implement the low contention global version-clock from the paper
// - make a test with multiple tvars
// - augment possible behavior when failing a transaction

#[derive(Clone, Default)]
pub struct Stm {
    // Global clock giving the number of transactions that have been committed
    clock: Arc<AtomicUsize>,
    transaction_ids: Arc<AtomicUsize>,
}

impl Stm {
    pub fn get_clock(&self) -> usize {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn increment_clock(&self) -> usize {
        self.clock.fetch_add(1, Ordering::SeqCst);
        self.clock.load(Ordering::SeqCst)
    }

    pub fn increment_tx_ids(&self) -> usize {
        self.transaction_ids.fetch_add(1, Ordering::SeqCst);
        self.transaction_ids.load(Ordering::SeqCst)
    }

    /// This runs a transaction with the given context. The TL2 algorithm makes
    /// a distinction between write and read transactions. Calling this function
    /// will start a read-write transaction according to this algorithm:
    ///
    /// 1. Get Current Version
    ///    Sample the global version to detect changes to the transactable data
    /// 2. Speculative Execution
    ///    Try to run the transaction (eg. the function with the [`Transaction`] parameter). keep track of
    ///    the addresses loaded in the read set, and the address/value-to-be-written in a write set.
    ///    Check first, if a value has already been written in the write-set. return that value.
    /// 3. Lock all the tvar used during the speculative execution
    /// 4. Validate all the tvars used
    /// 5. Increment the global clock
    /// 6. Commit changes to memory
    ///
    /// Returns the transaction id when successful
    pub fn read_write<T, F>(&self, transaction: F) -> Result<usize, TxError>
    where
        F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync + Debug,
    {
        let tx_id = self.increment_tx_ids();

        // Try to execute and commit transaction until success
        loop {
            let mut tx = Transaction::<T>::new(self.get_clock(), tx_id);

            info!("TX({:?}): START. GLOBAL VERSION ({})", tx.id, self.get_clock());
            match transaction(&mut tx) {
                Ok(_) => {
                    // Lock all the used tvar
                    let locks = tx.lock_tvars_used();
                    if locks.is_err() {
                        info!("TX({:?}): Locking used TVars failed", tx.id);
                        continue;
                    }
                    let (locks, values) = locks.unwrap();

                    let wv = self.increment_clock();
                    info!("TX({:?}): INCREMENT GLOBAL VERSION: ({})", tx.id, wv);

                    // If no transactions have been committed since the creation
                    // of this transaction then no need to validate
                    let has_new_tx_commits = wv > tx.version + 1;
                    if has_new_tx_commits && tx.validate(&locks).is_err() {
                        info!("TX({:?}): VALIDATING READ SET FAILED", tx.id);
                        continue;
                    }

                    if tx.commit(wv, locks, values).is_err() {
                        info!("TX({:?}): COMMITTING VALUE FAILED", tx.id);
                        continue;
                    };

                    break;
                }
                Err(e) => {
                    // TODO add potential new behavior, currently we try infinitely
                    info!("TX({:?}): Speculative execution failed. Retrying", tx.id);
                    // match strategy {
                    //     Strategy::Abort => return Err(TxError::Failed),
                    //     Strategy::Retry => continue,
                    // }
                }
            }
        }
        Ok(tx_id)
    }

    /// This runs a transaction with the given context. The TL2 algorithm makes
    /// a distinction between write and read transactions. Calling this function
    /// will start a read transaction according to this algorithm:
    ///
    /// 1. Get Current Version
    ///    Sample the global version to detect changes to the transactable data
    /// 2. Speculative Execution
    /// 3. Lock the tvars used
    /// 4. No need to increment the global clock
    /// 5. Check version consistency of the tvars used
    /// 6. No need to commit
    pub fn read_only<T, F>(&self, transaction: F) -> Result<usize, TxError>
    where
        F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
        T: Clone + Send + Sync + Debug,
    {
        let tx_id = self.increment_tx_ids();
        loop {
            let mut tx = Transaction::<T>::new(self.get_clock(), tx_id);
            match transaction(&mut tx) {
                Ok(_) => {
                    // Lock all the used tvar
                    let locks = tx.lock_tvars_used();
                    if locks.is_err() {
                        info!("TX_RO({:?}): Locking used TVars failed", tx.id);
                        continue;
                    }
                    let (locks, _) = locks.unwrap();

                    let has_new_tx_commits = self.get_clock() == tx.version;
                    if has_new_tx_commits && tx.validate(&locks).is_err() {
                        info!("TX_RO({:?}): VALIDATING READ SET FAILED", tx.id);
                        continue;
                    }
                    break;
                }
                Err(e) => continue, // TODO: this can be augmented with a strategy
            }
        }
        Ok(tx_id)
    }

    /// This will create a new transactional variable [`TVar`].
    pub fn create<T>(&self, val: T) -> TVar<T>
    where
        T: Clone + Debug,
    {
        TVar::new(val, self.get_clock())
    }
}

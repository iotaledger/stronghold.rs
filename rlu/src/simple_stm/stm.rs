use crate::simple_stm::error::TxError;
use crate::simple_stm::transaction::Transaction;
use crate::simple_stm::tvar::TVar;
use log::*;
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

//TODO:
// - implement the low contention global version-clock from the paper
// - treat read and write of tvars differently
// - make a test with multiple tvars
// - augment possible behavior when failing a transaction


#[derive(Clone, Default)]
struct Stm {
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

                    if tx.validate(&locks).is_err() {
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
    ///    Try to run the transaction (eg. the function with the [`Transaction`] parameter). keep track of
    ///    the addresses loaded in the read set, and the address/value-to-be-written in a write set.
    ///    Check first, if a value has already been written in the write-set. return that value.
    // TODO
    // pub fn read_only<T, F>(&self, transaction: F) -> Result<(), TxError>
    // where
    //     F: Fn(&mut Transaction<T>) -> Result<(), TxError>,
    //     T: Clone + Send + Sync + Debug,
    // {
    // loop {
    //     let mut tx = Transaction::<T>::new(self.get_clock(), self.increment_tx_ids());
    //     match transaction(&mut tx) {
    //         Ok(_) => {
    //             break;
    //         }
    //         Err(e) => continue, // TODO: this can be augmented with a strategy
    //     }
    // }
    // Ok(())
    // }

    /// This will create a new transactional variable [`TVar`].
    pub fn create<T>(&self, val: T) -> TVar<T>
    where
        T: Clone + Debug,
    {
        TVar::new(val, self.get_clock())
    }
}

#[cfg(test)]
mod tests {
    use crate::simple_stm::{stm::Stm, transaction::Transaction, tvar::TVar};
    use std::collections::HashSet;
    use threadpool::ThreadPool;

    #[allow(unused_imports)]
    use log::*;

    #[test]
    fn test_stm_basic() {
        #[cfg(feature = "verbose")]
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .init();

        let stm = Stm::default();

        let bank_alice = stm.create(10usize);
        let bank_bob = stm.create(100);
        let bank_charly = stm.create(0);

        let ba = bank_alice.clone();
        let bb = bank_bob.clone();
        let bc = bank_charly.clone();

        let transfer_bob_charly = 30;
        let alice_bonus = 40;
        let result = stm.read_write(
            move |tx: &mut Transaction<_>| {
                let mut amt_alice = tx.load(&ba)?;
                let mut amt_bob = tx.load(&bb)?;
                let mut amt_charly = tx.load(&bc)?;
                amt_alice += alice_bonus;
                amt_bob -= transfer_bob_charly;
                amt_charly += transfer_bob_charly;

                tx.store(&ba, amt_alice)?;
                tx.store(&bb, amt_bob)?;
                tx.store(&bc, amt_charly)?;

                Ok(())
            }
        );

        assert!(result.is_ok(), "Transaction failed");

        assert_eq!(bank_alice.try_get_data(), Ok(50));
        assert_eq!(bank_bob.try_get_data(), Ok(70));
        assert_eq!(bank_charly.try_get_data(), Ok(30));
    }

    #[test]
    // #[cfg(feature = "threaded")]
    fn test_stm_threaded_one_tvar() {
        use rand::{distributions::Bernoulli, prelude::Distribution};

        #[cfg(feature = "verbose")]
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .init();

        let stm = Stm::default();
        let entries: usize = 1000;

        // bernoulli distribution over reads vs read/write transactions
        let distribution = Bernoulli::new(0.7).unwrap();

        let mut expected: HashSet<String> = (0..entries).map(|e: usize| format!("{:04}", e)).collect();

        let set: TVar<HashSet<String>> = stm.create(HashSet::new());
        let pool = ThreadPool::new(8);

        let mut removal = HashSet::new();

        for value in expected.iter() {
            let stm_a = stm.clone();
            let set_a = set.clone();
            let set_debug = set.clone();
            let stm_debug = stm.clone();
            let value = value.clone();

            let is_readonly = distribution.sample(&mut rand::thread_rng());
            // TODO we don't handle readonly transaction yet
            let is_readonly = false;

            // We store the value that won't be written
            if is_readonly {
                removal.insert(value.clone());
            }

            pool.execute(move || {
                let result = {
                    match is_readonly {
                        false =>
                            {
                              let id =
                                    stm_a.read_write(
                                        move |tx: &mut Transaction<_>| {

                                            info!("TX({}):\n?????START?????\nGlobal Clock: {}\nSet: {:?}", tx.id, stm_debug.get_clock(), set_a);
                                            let mut inner = tx.load(&set_a)?;
                                            inner.insert(value.clone());
                                            tx.store(&set_a, inner.clone())?;
                                            Ok(())
                                        }
                                    );
                                if let Ok(id) = id {
                                    info!("TX({}):\n##### SUCCESS #####\nGlobal Clock: {}\nSet: {:?}", id, stm_a.get_clock(), set_debug);
                                } else {
                                    info!("TX(): FAILURE\nSet: {:?}",  set_debug);
                                }
                            },

                        true => todo!(),
                        // stm_a.read_only(move |tx: &mut Transaction<_>| {
                        //     let inner = tx.load(&set_a);
                        //     Ok(())
                        // }),
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

        let result = set.try_get_data();
        assert!(result.is_ok());

        let actual = result.unwrap();
        // assert!(false);

        assert!(
            expected == actual,
            "Actual collection is not equal to expected collection: missing {:?}",
            expected.symmetric_difference(&actual)
        );
    }
}

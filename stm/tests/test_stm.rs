// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::{distributions::Bernoulli, prelude::Distribution, Rng};
use std::collections::HashSet;
use stm::stm::{
    error::TxError,
    stm::{Stm, TxResult},
    transaction::Transaction,
    tvar::TVar,
};
use stronghold_stm as stm;
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
    let result = stm.read_write(move |tx: &mut Transaction<_>| {
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
    });

    assert!(result.is_ok(), "Transaction failed");

    assert_eq!(bank_alice.try_get_data(), Ok(50));
    assert_eq!(bank_bob.try_get_data(), Ok(70));
    assert_eq!(bank_charly.try_get_data(), Ok(30));
}

#[test]
// #[cfg(feature = "threaded")]
fn test_stm_threaded_one_tvar() {
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

        let read_percent = distribution.sample(&mut rand::thread_rng());

        // We store the value that won't be written
        if read_percent {
            removal.insert(value.clone());
        }

        pool.execute(move || {
            let result = {
                match read_percent {
                    false => {
                        let result = stm_a.read_write(move |tx: &mut Transaction<_>| {
                            info!(
                                "TX({}):\n?????START?????\nGlobal Clock: {}\nSet: {:?}",
                                tx.id,
                                stm_debug.get_clock(),
                                set_a
                            );
                            let mut inner = tx.load(&set_a)?;
                            inner.insert(value.clone());
                            tx.store(&set_a, inner.clone())?;
                            Ok(())
                        });
                        if let Ok(ref res) = result {
                            info!(
                                "TX({}):\n##### SUCCESS #####\nGlobal Clock: {}\nSet: {:?}",
                                res.tx_id,
                                stm_a.get_clock(),
                                set_debug
                            );
                        } else {
                            info!("TX(): FAILURE\nSet: {:?}", set_debug);
                        }
                        result
                    }

                    true => stm_a.read_only(move |tx: &mut Transaction<_>| {
                        let _inner = tx.load(&set_a);
                        Ok(())
                    }),
                }
            };

            assert!(result.is_ok(), "Failed to run transaction");
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

#[test]
fn test_multiple_readers_single_writer_single_thread() {
    const EXPECTED: usize = 15usize;

    let stm = Stm::default();

    let tvar: TVar<usize> = stm.create(6usize);

    let tvar1 = tvar.clone();
    let stm1 = stm.clone();

    assert!(stm1
        .read_write(move |tx: &mut Transaction<_>| {
            let data = tx.load(&tvar1)?;
            tx.store(&tvar1, data + 9)?;
            Ok(())
        })
        .is_ok());

    for _ in 0..10000 {
        let tvar1 = tvar.clone();
        let stm1 = stm.clone();

        assert!(stm1
            .read_only(move |tx: &mut Transaction<_>| {
                let data = tx.load(&tvar1)?;
                if data == EXPECTED {
                    Ok(())
                } else {
                    Err(TxError::Failed)
                }
            })
            .is_ok());
    }

    let value = tvar.take().unwrap();
    assert_eq!(value, EXPECTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_mutliple_readers_single_writer_async() {
    const EXPECTED: usize = 15usize;

    let stm = Stm::default();

    let tvar: TVar<usize> = stm.create(6usize);

    let tvar1 = tvar.clone();
    let stm1 = stm.clone();

    let j0 = tokio::spawn(async move {
        stm1.read_write(move |tx: &mut Transaction<_>| {
            let data = tx.load(&tvar1)?;
            tx.store(&tvar1, data + 9)?;
            Ok(())
        })
    });

    let mut threads = Vec::new();
    for _ in 0..10000 {
        let tvar1 = tvar.clone();
        let stm1 = stm.clone();

        let j1 = tokio::spawn(async move {
            stm1.read_only(move |tx: &mut Transaction<_>| {
                let data = tx.load(&tvar1)?;
                if data == EXPECTED {
                    Ok(())
                } else {
                    Err(TxError::Failed)
                }
            })
        });
        threads.push(j1)
    }

    j0.await.expect("Failed to join writer thread").unwrap();
    for j in threads {
        j.await.expect("Failed to join reader thread").unwrap();
    }

    let value = tvar.take().unwrap();
    assert_eq!(value, EXPECTED);
}

// Additional tests taken from the paper:
// [Testing patterns for software transactional memory engines](https://www.researchgate.net/publication/220854689_Testing_patterns_for_software_transactional_memory_engines)

// High frequency of variables being added/removed from the transactional space
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_paper_1() {
    const NB_MSG: usize = 5000;
    let msg_in_the_list = "In the vec";

    let stm = Stm::default();
    let init_v = vec![String::from(msg_in_the_list); NB_MSG];
    let tvar: TVar<Vec<String>> = stm.create(init_v);

    // objects for thread1
    let tvar1 = tvar.clone();
    let stm1 = stm.clone();
    // objects for thread2
    let tvar2 = tvar.clone();
    let stm2 = stm.clone();

    // Thread1 iterate through the list and check that strings are correct
    // This is done as long as elements remain in the list
    // let t1: JoinHandle<Output=Result<(), TxError>> = tokio::spawn(async move {
    let t1 = tokio::spawn(async move {
        loop {
            // Iter through the list and check content
            let tvar = tvar1.clone();
            let is_empty: TxResult<bool> = stm1.read_only(move |tx: &mut Transaction<_>| {
                let v = tx.load(&tvar)?;
                for s in v.iter() {
                    assert_eq!(*s, String::from(msg_in_the_list));
                }
                Ok(v.is_empty())
            })?;

            if is_empty.res {
                break;
            }
        }
        Ok::<(), TxError>(())
    });

    // Thread2 remove a random element from the list and clear the string
    let t2 = tokio::spawn(async move {
        for _ in 0..NB_MSG {
            let tvar = tvar2.clone();
            stm2.read_write(move |tx: &mut Transaction<_>| {
                let mut v = tx.load(&tvar)?;
                let rand_index = rand::thread_rng().gen_range(0..v.len());
                let mut s = v.remove(rand_index);
                s.clear();
                tx.store(&tvar, v)?;
                Ok(())
            })?;
            // Trying to free the tvar should result in an error
            assert!(tvar2.clone().take().is_err());
        }
        Ok::<(), TxError>(())
    });

    t1.await.expect("Failed to join").unwrap();
    t2.await.expect("Failed to join").unwrap();

    let value = tvar.take().unwrap();
    assert!(value.is_empty());
}

// High number of transactions on a single tvar to force a lot of abort/commit
#[tokio::test(flavor = "multi_thread", worker_threads = 32)]
async fn test_paper_2() {
    const SIZE: usize = 100;
    const NB_ITER: usize = 5000;
    const NB_THREADS: usize = 100;

    let stm = Stm::default();
    let init_v: Vec<usize> = vec![0; SIZE];
    let tvar = stm.create(init_v);

    let mut threads = Vec::new();

    // Threads keeps incrementing the nodes of the list
    for _ in 0..NB_THREADS {
        let tvar1 = tvar.clone();
        let stm1 = stm.clone();
        let t = tokio::spawn(async move {
            for _ in 0..NB_ITER {
                let tvar2 = tvar1.clone();
                stm1.read_write(move |tx: &mut Transaction<_>| {
                    let mut vec = tx.load(&tvar2)?;
                    for v in vec.iter_mut() {
                        *v += 1;
                    }
                    tx.store(&tvar2, vec)?;
                    Ok(())
                })?;
            }
            Ok::<(), TxError>(())
        });
        threads.push(t)
    }

    for t in threads.into_iter() {
        t.await.expect("Failed to join").unwrap();
    }

    let value = tvar.take().unwrap();
    assert_eq!(value, vec![NB_THREADS * NB_ITER; SIZE]);
}

// High number of transactional variables to check that collisions
// in the HashMap/HashSet of transactions if highly improbable
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_paper_3() {
    const NB_TVAR: usize = 50000;
    const NB_THREADS: usize = 10;

    let stm = Stm::default();
    let mut init_v: Vec<TVar<usize>> = vec![];
    for _ in 0..NB_TVAR {
        init_v.push(stm.create(0));
    }

    // Creating a vector containing the tvars for each thread
    let mut vectors: Vec<Vec<TVar<usize>>> = vec![];
    for _ in 0..NB_THREADS {
        let mut vector = vec![];
        for tvar in init_v.iter() {
            vector.push(tvar.clone())
        }
        vectors.push(vector);
    }

    // Each thread increment each tvar once
    let mut threads = vec![];
    for vector in vectors.into_iter() {
        let stm1 = stm.clone();
        let t = tokio::spawn(async move {
            stm1.read_write(move |tx: &mut Transaction<_>| {
                for tvar in vector.iter() {
                    let v = tx.load(tvar)?;
                    tx.store(tvar, v + 1)?;
                }
                Ok(())
            })?;
            Ok::<(), TxError>(())
        });
        threads.push(t);
    }

    for t in threads.into_iter() {
        t.await.expect("Failed to join").unwrap();
    }

    for tvar in init_v.into_iter() {
        let value = tvar.take().expect("wtf");
        assert_eq!(value, NB_THREADS);
    }
}

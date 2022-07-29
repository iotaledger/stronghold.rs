// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rlu::simple_stm::{stm::Stm, transaction::Transaction, tvar::TVar};
use std::collections::HashSet;
use stronghold_rlu as rlu;
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

        // We store the value that won't be written
        if is_readonly {
            removal.insert(value.clone());
        }

        pool.execute(move || {
            let result = {
                match is_readonly {
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
                        if let Ok(id) = result {
                            info!(
                                "TX({}):\n##### SUCCESS #####\nGlobal Clock: {}\nSet: {:?}",
                                id,
                                stm_a.get_clock(),
                                set_debug
                            );
                        } else {
                            info!("TX(): FAILURE\nSet: {:?}", set_debug);
                        }
                        result
                    }

                    true =>  
                        stm_a.read_only(move |tx: &mut Transaction<_>| {
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

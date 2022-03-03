// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rlu::{RLUStrategy, RLUVar, Read, RluContext, TransactionError, Write, RLU};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};
use stronghold_rlu as rlu;

#[cfg(test)]
#[ctor::ctor]
/// This function will be run before any of the tests
fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

#[test]
fn test_mutliple_readers_single_write() {
    const EXPECTED: usize = 15usize;

    let ctrl = RLU::new();
    let rlu_var: RLUVar<usize> = ctrl.create(6usize);

    let r1 = rlu_var.clone();
    let c1 = ctrl.clone();

    let j0 = std::thread::spawn(move || {
        match c1.execute(|mut context| {
            let mut data = context.get_mut(&r1)?;
            let inner = &mut *data;
            *inner += 9usize;

            Ok(())
        }) {
            Err(err) => Err(err),
            Ok(()) => Ok(()),
        }
        .expect("Failed");
    });
    let mut threads = Vec::new();

    for _ in 0..10000 {
        let r1 = rlu_var.clone();
        let c1 = ctrl.clone();

        let j1 = std::thread::spawn(move || {
            let context_fn = |context: RluContext<usize>| {
                let data = context.get(&r1);
                match *data {
                    Ok(inner) if **inner == EXPECTED => Ok(()),
                    Ok(inner) if **inner != EXPECTED => Err(TransactionError::Inner(format!(
                        "Value is not expected: actual {}, expected {}",
                        **inner, EXPECTED
                    ))),
                    Ok(_) => unreachable!("You shouldn't see this"),
                    Err(_) => Err(TransactionError::Failed),
                }
            };

            if c1.execute(context_fn).is_err() {
                // handle error
            }
        });

        threads.push(j1);
    }

    j0.join().expect("Failed to join writer thread");

    for j in threads {
        j.join().expect("Failed to join reader thread");
    }

    let value = rlu_var.get();
    assert_eq!(value, &15)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_mutliple_readers_single_write_async() {
    const EXPECTED: usize = 15usize;

    let ctrl = RLU::new();
    let rlu_var: RLUVar<usize> = ctrl.create(6usize);

    let r1 = rlu_var.clone();
    let c1 = ctrl.clone();

    let j0 = tokio::spawn(async move {
        match c1.execute(|mut context| {
            let mut data = context.get_mut(&r1)?;
            let inner = &mut *data;
            *inner += 9usize;

            Ok(())
        }) {
            Err(err) => Err(err),
            Ok(()) => Ok(()),
        }
        .expect("Failed");
    });
    let mut threads = Vec::new();

    for _ in 0..10000 {
        let r1 = rlu_var.clone();
        let c1 = ctrl.clone();

        let j1 = tokio::spawn(async move {
            let context_fn = |context: RluContext<usize>| {
                let data = context.get(&r1);
                match *data {
                    Ok(inner) if **inner == EXPECTED => Ok(()),
                    Ok(inner) if **inner != EXPECTED => Err(TransactionError::Failed),
                    _ => Err(TransactionError::Failed), /* FIXME: this could be another error and should be handled
                                                         * appropriately */
                }
            };

            assert!(c1.execute(context_fn).is_ok());
        });

        threads.push(j1);
    }

    j0.await.expect("Failed to join writer thread");

    for j in threads {
        j.await.expect("Failed to join reader thread");
    }

    let value = rlu_var.get();
    assert_eq!(value, &15)
}

#[test]
fn test_concurrent_reads_complex_type() {
    use std::thread::spawn;

    let c = RLU::default();

    let var = c.create(HashMap::<usize, &str>::new());

    let (vw_1, c1) = (var.clone(), c.clone());

    let (vr_1, c3) = (var.clone(), c.clone());
    let (vr_2, c4) = (var.clone(), c.clone());

    // writes
    let j0 = spawn(move || {
        c1.execute(|mut ctx| {
            let mut guard = ctx.get_mut(&vw_1)?;

            (*guard).insert(1234, "hello, world");

            Ok(())
        })
        .expect("Failed to write");
    });

    // reads
    let j1 = spawn(move || {
        c3.execute(|ctx| {
            let guard = ctx.get(&vr_1);

            if let Ok(inner) = *guard {
                let m = &**inner;
                match m.contains_key(&1234) {
                    true => return Ok(()),
                    false => return Err(TransactionError::Failed),
                }
            }

            Err(TransactionError::Failed)
        })
        .expect("Failed to read");
    });

    let j2 = spawn(move || {
        c4.execute(|ctx| {
            let guard = ctx.get(&vr_2);

            if let Ok(inner) = *guard {
                let m = &**inner;
                match m.contains_key(&1234) {
                    true => return Ok(()),
                    false => {
                        return Err(TransactionError::Failed);
                    }
                }
            }

            Err(TransactionError::Failed)
        })
        .expect("Failed to read");
    });

    [j0, j1, j2].into_iter().for_each(|thread| {
        thread.join().expect("Failed to join");
    });
}

#[test]
fn test_concurrent_reads_with_complex_type_with_strategy() {
    use std::thread::spawn;

    let c = RLU::with_strategy(RLUStrategy::Retry);
    let var = c.create(HashMap::<usize, &str>::new());
    let (vw_1, c1) = (var.clone(), c.clone());
    let (vr_1, c3) = (var.clone(), c.clone());
    let (vr_2, c4) = (var.clone(), c.clone());

    // writes
    let j0 = spawn(move || {
        c1.execute(|mut ctx| {
            let mut guard = ctx.get_mut(&vw_1)?;

            (*guard).insert(1234, "hello, world");

            Ok(())
        })
        .expect("Failed to write");
    });

    // reads
    let j1 = spawn(move || {
        c3.execute(|ctx| {
            let guard = ctx.get(&vr_1);

            if let Ok(inner) = *guard {
                let m = &**inner;
                match m.contains_key(&1234) {
                    true => return Ok(()),
                    false => return Err(TransactionError::Failed),
                }
            }

            Err(TransactionError::Failed)
        })
        .expect("Failed to read");
    });

    let j2 = spawn(move || {
        c4.execute(|ctx| {
            let guard = ctx.get(&vr_2);

            if let Ok(inner) = *guard {
                let m = &**inner;
                match m.contains_key(&1234) {
                    true => return Ok(()),
                    false => {
                        return Err(TransactionError::Failed);
                    }
                }
            }

            Err(TransactionError::Failed)
        })
        .expect("Failed to read");
    });

    [j0, j1, j2].into_iter().for_each(|thread| {
        thread.join().expect("Failed to join");
    });
}

#[test]
fn test_concurrent_reads_and_writes_with_complex_type_with_strategy() {
    use std::thread::spawn;

    let failures = Arc::new(AtomicUsize::new(0));
    let num_test_runs = 1000;
    for _ in 0..num_test_runs {
        let c = RLU::with_strategy(RLUStrategy::Abort);
        let var = c.create(HashMap::<usize, &str>::new());

        let runs = 8;

        let mut threads = Vec::new();

        // writes
        for i in 0..runs {
            let ctrl = c.clone();
            let var = var.clone();

            let j0 = spawn(move || {
                ctrl.execute(|mut ctx| {
                    let mut guard = ctx.get_mut(&var)?;

                    (*guard).insert(i, "hello, world");

                    Ok(())
                })
                .expect("Failed to write");
            });

            threads.push(j0);
        }

        // reads
        for i in 0..runs {
            let ctrl = c.clone();
            let var = var.clone();
            let fail = failures.clone();

            let j1 = spawn(move || {
                let result = ctrl.execute(|ctx| {
                    let guard = ctx.get(&var);

                    if let Ok(inner) = *guard {
                        let m = &**inner;

                        match m.contains_key(&i) {
                            true => return Ok(()),
                            false => {
                                std::thread::sleep(Duration::from_millis(1));
                                return Err(TransactionError::Failed);
                            }
                        }
                    }

                    Err(TransactionError::Failed)
                });

                if result.is_err() {
                    // handle error?
                }

                if !var.get().contains_key(&i) {
                    fail.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });

            threads.push(j1);
        }

        threads.into_iter().for_each(|thread| {
            thread.join().expect("Failed to join");
        });
    }

    println!(
        "number of failures: {}%",
        (failures.load(std::sync::atomic::Ordering::SeqCst)) as f64 / num_test_runs as f64 * 100.0
    );
}

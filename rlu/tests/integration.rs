// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rlu::{NonBlockingQueue, NonBlockingStack, Queue, RLUVar, Read, RluContext, Stack, TransactionError, Write, RLU};
use std::collections::HashMap;
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
                    Err(_) => Err(TransactionError::Retry),
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
                    Ok(inner) if **inner != EXPECTED => Err(TransactionError::Retry),
                    _ => Err(TransactionError::Retry), /* FIXME: this could be another error and should be handled
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
fn test_stack() {
    let stack = NonBlockingStack::default();
    let end = 10000;

    (0..=end).for_each(|n| stack.push(n));
    (0..=end).rev().for_each(|n| assert_eq!(Some(&n), stack.pop()));

    assert_eq!(None, stack.pop());
}

#[test]
fn test_queue() {
    let queue = NonBlockingQueue::default();
    let end = 2;

    (0..=end).for_each(|n| queue.put(n));
    (0..=end).for_each(|n| assert_eq!(Some(&n), queue.poll()));

    assert_eq!(None, queue.poll());
}

#[ignore]
#[test]
fn test_queue_threaded() {
    let queue = NonBlockingQueue::default();

    let mut workers = Vec::new();
    let runs = 8;

    for i in 0..runs {
        let q = queue.clone();
        workers.push(std::thread::spawn(move || q.put(i)));
    }

    for _ in 0..runs {
        let q = queue.clone();
        workers.push(std::thread::spawn(move || {
            q.poll();
        }));
    }

    for t in workers {
        t.join().expect("Failed to join thread");
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_queue_async() {
    let queue = NonBlockingQueue::default();

    let mut workers = Vec::new();
    let runs = 16;

    for i in 0..runs {
        let q = queue.clone();

        workers.push(tokio::spawn(async move {
            q.put(i);
        }));
    }

    for _ in 0..runs {
        let q = queue.clone();
        workers.push(tokio::spawn(async move {
            match q.poll() {
                Some(inner) => {
                    println!("inner: {}", inner);
                }
                None => {
                    println!("got none");
                }
            }
        }));
    }

    for t in workers {
        t.await.expect("Failed to join thread");
    }
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
            drop(guard);

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
                    false => return Err(TransactionError::Retry),
                }
            }

            Err(TransactionError::Retry)
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
                        drop(guard);
                        return Err(TransactionError::Retry);
                    }
                }
            }

            Err(TransactionError::Retry)
        })
        .expect("Failed to read");
    });

    [j0, j1, j2].into_iter().for_each(|thread| {
        thread.join().expect("Failed to join");
    });
}

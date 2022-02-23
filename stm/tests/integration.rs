// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_stm::{NonBlockingQueue, NonBlockingStack, Queue, RLUVar, RluContext, Stack, TransactionError, RLU};

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

    for _ in 0..1000 {
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
                    Err(_) => Err(TransactionError::Abort),
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

#[test]
fn test_queue_concurrent() {
    let queue = NonBlockingQueue::default();

    let mut workers = Vec::new();
    let runs = 32;

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

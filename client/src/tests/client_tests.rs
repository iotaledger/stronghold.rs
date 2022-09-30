// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Client;
use threadpool::ThreadPool;
use std::thread;
use std::time::Duration;

#[test]
fn test_multithreaded_store() {
    const NB_INPUTS: usize = 100;

    let pool = ThreadPool::new(8);
    let main_cl = Client::default();

    for i in 0..NB_INPUTS {
        let cl = main_cl.clone();
        pool.execute(move || {
            let k1 = format!("key1{}", i).into_bytes();
            let v1 = format!("value2{}", i).into_bytes();
            let k2 = format!("key2{}", i).into_bytes();
            let v2 = format!("value2{}", i).into_bytes();
            let s1 = cl.store();
            let s2 = cl.store();
            s1.insert(k1, v1, None).unwrap();
            s2.insert(k2, v2, None).unwrap();
        });
    }
    pool.join();

    // Verify operations
    for i in 0..NB_INPUTS {
        let k1 = format!("key1{}", i).into_bytes();
        let expected_v1 = format!("value2{}", i).into_bytes();
        let k2 = format!("key2{}", i).into_bytes();
        let expected_v2 = format!("value2{}", i).into_bytes();

        let expected_value = format!("value{}", i).into_bytes();
        let v1 = main_cl.store().get(&k1).unwrap();
        let v2 = main_cl.store().get(&k2).unwrap();
        assert_eq!(v1, Some(expected_v1));
        assert_eq!(v2, Some(expected_v2));
    }
}

fn test_client_share_store() {
    let main_cl = Client::default();
    let cl1 = main_cl.clone();
    let cl2 = main_cl.clone();

    let main_k1 = format!("key1").into_bytes();
    let main_k2 = format!("key2").into_bytes();
    let main_v1 = format!("value1").into_bytes();
    let main_v2 = format!("value2").into_bytes();

    let k1 = main_k1.clone();
    let k2 = main_k2.clone();
    let v1 = main_v1.clone();
    let v2 = main_v2.clone();

    // Thread 1 insert a value and wait for thread 2 to insert another value
    let t1 = thread::spawn(move || {
        let s = cl1.store();
        s.insert(k1, v1, None).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert_eq!(s.get(&k2).unwrap(), Some(v2));
    });

    let k1 = main_k1.clone();
    let k2 = main_k2.clone();
    let v1 = main_v1.clone();
    let v2 = main_v2.clone();
    let t2 = thread::spawn(move || {
        let s = cl2.store();
        s.insert(k2, v2, None).unwrap();
        assert_eq!(s.get(&k1).unwrap(), None);
    });

    t1.join().unwrap();
    t2.join().unwrap();
    assert_eq!(main_cl.store().get(&main_k1).unwrap(), Some(main_v1));
    assert_eq!(main_cl.store().get(&main_k2).unwrap(), Some(main_v2));
}

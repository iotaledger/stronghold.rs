// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use stronghold_stm::{transactional, TVar, Transaction};

fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

#[tokio::test]
async fn test_single_transaction() {
    init_logger();

    let var: TVar<usize> = TVar::new(21);
    let v2 = var.clone();

    assert!(transactional(move |tx: &Transaction<usize>| {
        let a = tx.read(&v2).unwrap();
        tx.write(*a + 42, &v2).unwrap();
        Ok(())
    })
    .await
    .is_ok());

    assert_eq!(var.read_atomic().unwrap(), Arc::new(63));
}

#[tokio::test]
async fn test_multiple_transactions() {
    init_logger();

    let var: TVar<usize> = TVar::new(21);
    let v2 = var.clone();
    let v3 = var.clone();

    let r2 = tokio::spawn(transactional(move |tx: &Transaction<usize>| {
        tx.write(42, &v3).unwrap();
        Ok(())
    }));

    let r1 = tokio::spawn(transactional(move |tx: &Transaction<usize>| {
        let a = tx.read(&v2).unwrap();
        tx.write(*a + 42, &v2).unwrap();
        Ok(())
    }));

    r1.await
        .expect("Could not join task")
        .expect("Transaction error occured");
    r2.await
        .expect("Could not join task")
        .expect("Transaction error occured");

    assert_eq!(var.read_atomic().unwrap(), Arc::new(84));
}

#[tokio::test]
async fn test_multiple_access() {
    init_logger();

    let var: TVar<usize> = TVar::new(33);

    let result = var.read_atomic();
    assert!(result.is_ok());
    assert_eq!(result.expect("Failed to unwrap result"), Arc::new(33));
}

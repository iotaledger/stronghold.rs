// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use stronghold_stm::{transactional, TVar, Transaction};

#[tokio::test]
async fn test_single_transaction() {
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
    // TODO: test multiple transactions with either read/ write access
    todo!()
}

#[tokio::test]
async fn test_multiple_access() {
    let var: TVar<usize> = TVar::new(33);

    // TODO impl
    let result = var.read_atomic();
    assert!(result.is_ok());
    assert_eq!(result.expect("Failed to unwrap result"), Arc::new(33));
}

// #[tokio::test]
// async fn test_blocking_future() {
//     let expected = 1024usize;

//     let blocker = FutureBlocker::new(async move { Ok(expected) });
//     let b1 = blocker.clone();

//     let r1 = tokio::spawn(blocker);
//     let r2 = tokio::spawn(async move { b1.wake().await });

//     let actual = r1.await.expect("Unable to join task").expect("Transaction failure");

//     assert_eq!(actual, expected);
//     r2.await.expect("");
// }

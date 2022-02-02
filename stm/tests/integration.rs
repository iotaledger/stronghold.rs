// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use stronghold_stm::*;

#[tokio::test]
async fn test_single_transaction() {
    let var: TVar<usize> = TVar::new(21);

    assert!(transactional(|tx: Arc<Transaction<usize>>| {
        let v1 = var.clone();

        Box::pin(async move {
            let a = tx.read(&v1).await.unwrap();
            tx.write(a + 42, &v1).await.unwrap();
            Ok(())
        })
    })
    .await
    .is_ok());

    assert_eq!(var.read_atomic().unwrap(), 63);
}

#[tokio::test]
async fn test_multiple_transactions() {
    // TODO: test multiple transactions with either read/ write access
    todo!()
}

#[tokio::test]
async fn test_multiple_access() {
    let var: TVar<usize> = TVar::new(0);

    // TODO impl
    let result = var.read_atomic();
    assert!(result.is_ok());
    assert_eq!(result.expect("Failed to unwrap result"), 33);
}

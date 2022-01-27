// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{BoxedMemory, TLog, TVar, TransactionError};
use std::{collections::BTreeMap, future::Future};

/// Defines a transaction strategy. Strategies vary
/// how transactions should be handled in case the commit
/// to memory fails.
pub enum Strategy {
    /// Aborts the transaction, so the user must try at an another point
    /// in time.
    Abort,

    /// Retries the transaction until it success. This is the default case,
    /// if no other `Strategy` is being provided
    Retry,
}

pub struct Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    log: BTreeMap<String, TLog<T>>,
}

impl<T> Transaction<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn new() -> Self {
        Self { log: BTreeMap::new() }
    }

    pub async fn with_func<F, W>(func: F) -> Result<T, TransactionError>
    where
        F: FnOnce(Self) -> W,
        W: Future<Output = Result<(), TransactionError>>,
    {
        todo!()
    }

    pub async fn read(&self, var: &TVar<T>) -> Result<T, TransactionError> {
        todo!()
    }

    pub async fn write(&self, value: T, var: &TVar<T>) -> Result<(), TransactionError> {
        todo!()
    }

    async fn commit(&self) -> Result<(), TransactionError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {}

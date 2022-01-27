// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{BoxedMemory, Transaction, TransactionError};
use std::sync::{Arc, Mutex};

/// Represents a transactional variable, that
/// can be read from and written to.
pub struct TVar<T> {
    /// this is a controller to takae care of access to the
    /// underlying value.
    /// TODO: Mutex to value must be replaced
    ctrl: Arc<Mutex<T>>,
}

impl<T> TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub fn new(var: T) -> Self {
        Self {
            ctrl: Arc::new(Mutex::new(var)),
        }
    }

    /// Reads the value of the inner value without a transaction
    pub async fn read_atomic(&self) -> T {
        todo!()
    }

    /// Writes to the inner value without a transaction
    pub async fn write_atomic(&self, value: T) {
        todo!()
    }

    /// Read the value from a transaction. This is considered the "normal" way
    pub async fn read(&self, tx: &Transaction<T>) -> Result<T, TransactionError> {
        todo!()
    }

    /// Write a value into the transaction
    pub async fn write(&self, value: T, tx: &Transaction<T>) -> Result<(), TransactionError> {
        todo!()
    }

    /// Applies a function to change the value inside a transaction
    pub async fn apply<F>(&self, func: F, tx: &Transaction<T>) -> Result<(), TransactionError>
    where
        F: FnOnce(T) -> T,
    {
        match self.read(tx).await {
            Ok(value) => self.write(func(value), tx).await,
            Err(error) => Err(error),
        }
    }
}

impl<T> Clone for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            ctrl: self.ctrl.clone(),
        }
    }
}

/// Transactional Log type. The intend of this type
/// is to track each operation on the target value
pub enum TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    /// Indicates that a variable has been read
    Read(T),

    /// Indicates that a variable has been modified
    Write(T),
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_read() {}

    #[tokio::test]
    async fn test_write() {}

    #[tokio::test]
    async fn test_apply() {}
}

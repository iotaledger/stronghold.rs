// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

use crate::{BoxedMemory, TransactionError};
use std::{
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

/// Represents a transactional variable, that
/// can be read from and written to.
pub struct TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    /// this is a controller to take care of access to the
    /// underlying value.
    /// TODO: Mutex to value must be replaced
    value: Arc<Mutex<T>>,
}

impl<T> TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub fn new(var: T) -> Self {
        Self {
            value: Arc::new(Mutex::new(var)),
        }
    }

    /// Reads the value of the inner value without a transaction
    /// FIXME: Do we really need this function,  or is this "only" required
    /// for tests
    pub fn read_atomic(&self) -> Result<T, TransactionError> {
        let value = &self.value.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;

        // FIXME: this would require `BoxedMemory` to support safe cloning of memory
        Ok((*value).clone())
    }

    pub fn write_atomic(&self, value: T) -> Result<(), TransactionError> {
        let mut inner = self.value.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;

        *inner = value;

        Ok(())
    }

    // /// Read the value from a transaction. This is considered the "normal" way
    // pub async fn read(&self, tx: &Transaction<T>) -> Result<T, TransactionError> {
    //     tx.read(self).await
    // }

    // /// Write a value into the transaction
    // pub async fn write(&self, value: T, tx: &Transaction<F, T>) -> Result<(), TransactionError> {
    //     tx.write(value, self).await
    // }

    // /// Applies a function to change the value inside a transaction
    // pub async fn apply<P>(&self, func: P, tx: &Transaction<F, T>) -> Result<(), TransactionError>
    // where
    //     P: FnOnce(T) -> T,
    // {
    //     match self.read(tx).await {
    //         Ok(value) => self.write(func(value), tx).await,
    //         Err(error) => Err(error),
    //     }
    // }

    /// Returns `true`, if the referenced values are equal
    pub fn equals(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
    }
}

impl<T> Clone for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> PartialEq for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        let a = &self as *const _ as *const usize as usize;
        let b = &other as *const _ as *const usize as usize;

        // we compare only the pointers to store [`TVar`] inside a map
        a == b
    }
}

impl<T> Eq for TVar<T> where T: Send + Sync + BoxedMemory {}

impl<T> Hash for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize((&self as *const _ as *const usize) as usize);
        state.finish();
    }
}

/// Transactional Log type. The intend of this type
/// is to track each operation on the target value
#[derive(Zeroize)]
pub enum TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    /// Indicates that a variable has been read
    Read(T),

    /// Indicates that a variable has been modified
    Write(T),
}

impl<T> TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub async fn read(&self) -> Result<T, TransactionError> {
        todo!()
    }

    pub async fn write(&self, _: T) -> Result<(), TransactionError> {
        todo!()
    }
}

impl<T> Deref for TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Read(inner) => inner,
            Self::Write(inner) => inner,
        }
    }
}

impl<T> DerefMut for TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Read(inner) => inner,
            Self::Write(inner) => inner,
        }
    }
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

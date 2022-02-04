// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

use crate::{ctrl::MemoryController, BoxedMemory, Transaction, TransactionError};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc,
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
    pub(crate) value: Option<MemoryController<Transaction<T>, T>>,
}

impl<T> TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub fn new(var: T) -> Self {
        Self {
            value: Some(MemoryController::new(var)),
        }
    }

    /// Reads the value of the inner value without a transaction
    /// FIXME: Do we really need this function,  or is this "only" required
    /// for tests
    pub fn read_atomic(&self) -> Result<Arc<T>, TransactionError> {
        if let Some(ctrl) = &self.value {
            match ctrl.value.read() {
                Ok(lock) => return Ok(lock.clone()),
                Err(error) => return Err(TransactionError::InconsistentState),
            }
        }

        Err(TransactionError::InconsistentState)

        // FIXME: this would require `BoxedMemory` to support safe cloning of memory
        // Ok((*value).clone())
    }

    pub fn write_atomic(&self, value: T) -> Result<(), TransactionError> {
        if let Some(ctrl) = &self.value {
            match ctrl.value.write() {
                Ok(mut lock) => {
                    *lock = Arc::new(value);

                    return Ok(());
                }
                Err(error) => return Err(TransactionError::InconsistentState),
            }
        }

        Err(TransactionError::InconsistentState)
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

    // Returns `true`, if the referenced values are equal
    // pub fn equals(&self, other: &Self) -> bool {
    //     Arc::ptr_eq(&self.value, &other.value)
    // }
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

impl<T> PartialOrd for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = &self as *const _ as *const usize as usize;
        let b = &other as *const _ as *const usize as usize;

        match a {
            _ if a > b => Some(Ordering::Greater),
            _ if a < b => Some(Ordering::Less),
            _ => Some(Ordering::Equal),
        }
    }
}

impl<T> Hash for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize((&self as *const _ as *const usize) as usize);
        state.finish();
    }
}

impl<T> Ord for TVar<T>
where
    T: Send + Sync + BoxedMemory,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &self as *const _ as *const usize as usize;
        let b = &other as *const _ as *const usize as usize;

        match a {
            _ if a > b => Ordering::Greater,
            _ if a < b => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}

impl<T> Eq for TVar<T> where T: Send + Sync + BoxedMemory {}

/// Transactional Log type. The intend of this type
/// is to track each operation on the target value
#[derive(Zeroize)]
pub enum TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    /// Indicates that a variable has been read
    Read(Arc<T>),

    /// Indicates that a variable has been modified
    Write(Arc<T>),

    /// Store (original, updated)
    ReadWrite(Arc<T>, Arc<T>),
}

impl<T> TLog<T>
where
    T: Send + Sync + BoxedMemory,
{
    pub fn read(&mut self) -> Result<Arc<T>, TransactionError> {
        match self {
            Self::Read(inner) => Ok(inner.clone()),
            Self::Write(ref inner) | Self::ReadWrite(_, ref inner) => Ok(inner.clone()),
        }
    }

    pub fn write(&mut self, update: T) -> Result<(), TransactionError> {
        *self = match self {
            Self::Write(ref inner) => Self::Write(inner.clone()),
            Self::Read(ref inner) | Self::ReadWrite(_, ref inner) => Self::ReadWrite(inner.clone(), Arc::new(update)),
        };

        Ok(())
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
            Self::ReadWrite(_, inner) => inner,
        }
    }
}

// impl<T> DerefMut for TLog<T>
// where
//     T: Send + Sync + BoxedMemory,
// {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         match self {
//             Self::Read(inner) => inner,
//             Self::Write(inner) => inner,
//             Self::ReadWrite(_, inner) => inner,
//         }
//     }
// }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ordering() {
        let a = 10;
        let b = 20;

        let order = match a {
            _ if a > b => Some(Ordering::Greater),
            _ if a < b => Some(Ordering::Less),
            _ => Some(Ordering::Equal),
        };

        println!("Ordering :{:?}", order)
    }

    #[tokio::test]
    async fn test_read() {}

    #[tokio::test]
    async fn test_write() {}

    #[tokio::test]
    async fn test_apply() {}
}

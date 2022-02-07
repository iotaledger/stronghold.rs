// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{transaction::TransactionControl, BoxedMemory, TransactionError};
use std::{
    future::Future,
    sync::{Arc, Mutex, RwLock, Weak},
};

/// The [`MemoryController`] weakly tracks futures,
/// that observe the oringal value. The [`MemoryController`]
/// will not be used directly, but is employed by [`Transaction`]
pub(crate) struct MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    /// A list of futures observing the underlying value
    futures: Arc<Mutex<Vec<Weak<F>>>>,

    // the actual value to be modified
    pub(crate) value: Arc<RwLock<Arc<T>>>,
}

/// Provide an implementation of [`Clone`], that returns
/// a copy of the pointers, but not the values
impl<F, T> Clone for MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            futures: self.futures.clone(),
            value: self.value.clone(),
        }
    }
}

impl<F, T> MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    pub fn new(value: T) -> Self {
        Self {
            futures: Arc::new(Mutex::new(Vec::new())),
            value: Arc::new(RwLock::new(Arc::new(value))),
        }
    }

    /// Garbage collect all inactive / dropped observers and keep
    /// only a list of still present ones.
    pub async fn gc(&self) -> Result<(), TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.retain(|weak_ref| weak_ref.upgrade().is_some());

        Ok(())
    }

    /// Wakes all observing futures to continue work
    pub fn wake_all(&self) -> Result<(), TransactionError> {
        let futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        for observer in futures.iter() {
            if let Some(observer) = observer.upgrade() {
                observer.wake();
            }
        }

        Ok(())
    }

    /// Adds another [`FutureBlocker`]
    pub fn push(&self, blocker: &Arc<F>) -> Result<(), TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.push(Arc::downgrade(blocker));

        Ok(())
    }

    pub fn address(&self) -> usize {
        self as *const _ as usize
    }
}

impl<F, T> PartialEq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        self.address().eq(&other.address())
    }
}

impl<F, T> Eq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
}

impl<F, T> PartialOrd for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let a = self as *const _ as usize;
        let b = other as *const _ as usize;

        Some(match a {
            _ if a > b => std::cmp::Ordering::Greater,
            _ if a < b => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        })
    }
}

impl<F, T> Ord for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self as *const _ as usize;
        let b = other as *const _ as usize;

        match a {
            _ if a > b => std::cmp::Ordering::Greater,
            _ if a < b => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

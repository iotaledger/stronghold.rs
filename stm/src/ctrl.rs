// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{transaction::TransactionControl, LockedMemory, TransactionError};
use log::*;
use std::{
    future::Future,
    sync::{Arc, Mutex, RwLock, Weak},
};

/// [`ControlResult`] is an additional return type
/// to indicate some further action on callers side
pub(crate) enum ControlResult {
    /// Waiting futures shall be waked
    Wake,

    /// No operation neccesary
    None,
}

/// The [`MemoryController`] weakly tracks futures,
/// that observe the oringal value. The [`MemoryController`]
/// will not be used directly, but is employed by [`Transaction`]
pub(crate) struct MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + LockedMemory,
{
    /// A list of futures observing the underlying value
    futures: Arc<Mutex<Vec<Weak<F>>>>,

    // the actual value to be modified
    value: Arc<RwLock<T>>,
}

impl<F, T> MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + LockedMemory,
{
    pub fn new(value: T) -> Self {
        Self {
            futures: Arc::new(Mutex::new(Vec::new())),
            value: Arc::new(RwLock::new(value)),
        }
    }

    /// Garbage collect all inactive / dropped observers and keep
    /// only a list of still present ones.
    pub fn cleanup(&self) -> Result<ControlResult, TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.retain(|weak_ref| weak_ref.upgrade().is_some());

        info!("MemoryControl:: Cleanup. Number of monitored futures {}", futures.len());
        // if only one future is inside the controller,
        // signal to wake it up
        match futures.len() {
            0 | 1 => {
                info!("MemoryControl: Tell transaction to wake");
                Ok(ControlResult::Wake)
            }
            _ => Ok(ControlResult::None),
        }
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

    /// Adds a [`Future`] for monitoring
    pub fn insert(&self, blocker: &Arc<F>) -> Result<(), TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.push(Arc::downgrade(blocker));

        info!("MemoryController:: Push to log. Size = {}", futures.len());

        Ok(())
    }

    pub fn read(&self) -> Result<Arc<T>, TransactionError> {
        let value = self.value.read().map_err(TransactionError::to_inner)?;

        // TODO: shalll we return a coned copy? but this would generate more inconsistencies, or not?
        Ok(Arc::new(value.clone()))
    }

    pub fn write(&self, value: T) -> Result<(), TransactionError> {
        let mut v = self.value.write().map_err(TransactionError::to_inner)?;
        *v = value;
        Ok(())
    }
}

impl<F, T> PartialEq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + LockedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        match self.read() {
            Ok(a) => match other.read() {
                Ok(b) => a == b,
                Err(_) => false,
            },
            Err(e) => false,
        }
    }
}

impl<F, T> Eq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + LockedMemory,
{
}

/// Provide an implementation of [`Clone`], that returns
/// a copy of the pointers, but not the values
impl<F, T> Clone for MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + LockedMemory,
{
    fn clone(&self) -> Self {
        Self {
            futures: self.futures.clone(),
            value: self.value.clone(),
        }
    }
}

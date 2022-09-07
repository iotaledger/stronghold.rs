// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::rlu::{guard::BaseGuard, Result, TransactionError, RLU};
use log::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, RwLock,
};

/// This type represents an rlu managed type. The type is is not being constructed directly
/// but with the help of [`RLU`].
pub struct RLUVar<T>
where
    T: Clone,
{
    pub(crate) inner: Arc<InnerVar<T>>,
}

impl<T> RLUVar<T>
where
    T: Clone,
{
    pub fn get(&self) -> T {
        self.inner.get()
    }

    /// Tries to get a [`BaseGuard`]
    pub fn try_inner(&self) -> Result<BaseGuard<'_, T>> {
        info!("Locking inner data");
        match self.inner.data.lock() {
            Ok(guard) => Ok(BaseGuard::new(guard, None)),
            Err(e) => Err(TransactionError::Inner(e.to_string())),
        }
    }

    /// Returns true, if this object is an original and references a copy
    pub(crate) fn is_locked(&self) -> bool {
        self.inner.copy.lock().expect("").is_some()
    }

    /// Returns true, if this object is an original and does not references a copy
    pub(crate) fn is_unlocked(&self) -> bool {
        self.inner.copy.lock().expect("").is_none()
    }
}

impl<T> From<T> for RLUVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        RLUVar {
            inner: Arc::new(InnerVar::from(value)),
        }
    }
}

impl<T> Clone for RLUVar<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct InnerVarCopy<T>
where
    T: Clone,
{
    pub locked_thread_id: Option<AtomicUsize>,
    pub data: Arc<RwLock<T>>,
    pub original: Arc<InnerVar<T>>,
}

impl<T> Clone for InnerVarCopy<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            locked_thread_id: self
                .locked_thread_id
                .as_ref()
                .map(|thread_id| AtomicUsize::new(thread_id.load(Ordering::SeqCst))),
            data: self.data.clone(),
            original: self.original.clone(),
        }
    }
}

impl<T> InnerVarCopy<T>
where
    T: Clone,
{
    /// Writes the data back to original
    ///
    /// # Safety
    ///
    /// This method is safe, as dereferencing ptr to original will be checked against null
    pub(crate) fn write_back(&self) -> Result<()> {
        let lock_id = self
            .locked_thread_id
            .as_ref()
            .map_or(-1, |inner| inner.load(Ordering::SeqCst) as isize);

        info!("({}) Locking data read", lock_id);
        let data_guard = self.data.try_read().expect("cannot get lock in copy -> data");
        let copy = data_guard.clone();
        info!("({}) Unlocking data read", lock_id);
        drop(data_guard);

        info!("({}) Locking original data", lock_id);
        let mut guard = self.original.data.try_lock().map_err(|e| TransactionError::Blocking)?;

        *guard = copy;

        info!("({}) Unlocking original data", lock_id);
        drop(guard);

        Ok(())
    }
}

pub struct InnerVar<T>
where
    T: Clone,
{
    pub locked_thread_id: Option<AtomicUsize>,
    pub ctrl: Option<RLU<T>>,
    pub data: Arc<Mutex<T>>,
    pub copy: Arc<Mutex<Option<InnerVarCopy<T>>>>,
}

impl<T> InnerVar<T>
where
    T: Clone,
{
    /// Returns true, if this object is an original and references a copy
    pub(crate) fn is_locked(&self) -> bool {
        self.copy.lock().expect("").is_some()
    }

    /// Returns true, if this object is an original and does not references a copy
    pub(crate) fn is_unlocked(&self) -> bool {
        self.copy.lock().expect("").is_none()
    }

    pub fn get(&self) -> T {
        self.data.lock().expect("").clone()
    }
}

impl<T> From<T> for InnerVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        Self {
            data: Arc::new(Mutex::new(value)),
            locked_thread_id: None,
            copy: Arc::new(Mutex::new(None)),
            ctrl: None,
        }
    }
}

impl<T> Clone for InnerVar<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            ctrl: self.ctrl.clone(),
            data: self.data.clone(),
            locked_thread_id: Some(AtomicUsize::new(match &self.locked_thread_id {
                Some(inner) => inner.load(Ordering::SeqCst),
                None => 0,
            })),
            copy: Arc::new(Mutex::new(None)),
        }
    }
}

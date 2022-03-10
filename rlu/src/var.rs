// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{guard::BaseGuard, Result, TransactionError, RLU};
use std::{
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

/// # RLUVar &lt;T&gt;
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
    /// This function returns the inner value, or None if the pointer is null
    // pub fn get(&self) -> Option<&T> {
    //     // match self.inner.load(Ordering::SeqCst) {
    //     //     ptr if ptr.is_null() => None,
    //     //     ptr => {
    //     //         let inner = unsafe { &*ptr };
    //     //         Some(&inner.data)
    //     //     }
    //     // }
    //     todo!()
    // }

    pub fn deref_data(&self) -> Result<BaseGuard<'_, T>> {
        match self.inner.data.lock() {
            Ok(guard) => Ok(BaseGuard::new(guard, None)),
            Err(e) => Err(TransactionError::Inner(e.to_string())),
        }
    }

    /// Returns true, if this object is an original and references a copy
    pub(crate) fn is_locked(&self) -> bool {
        self.inner.copy.is_some()
    }

    /// Returns true, if this object is an original and does not references a copy
    pub(crate) fn is_unlocked(&self) -> bool {
        self.inner.copy.is_none()
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

impl<T> Deref for RLUVar<T>
where
    T: Clone,
{
    type Target = InnerVar<T>;

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

pub struct InnerVarCopy<T>
where
    T: Clone,
{
    pub locked_thread_id: Option<AtomicUsize>,
    pub data: Arc<Mutex<T>>,
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
    #[allow(deref_nullptr)]
    /// Writes the data back to original
    ///
    /// # Safety
    ///
    /// This method is safe, as dereferencing ptr to original will be checked against null
    pub(crate) fn write_back(&self) {
        let inner = &self.original;
        let mut guard = inner.data.lock().expect("");

        *guard = self.data.lock().expect("Could not lock copy data").deref().clone();
    }
}

pub struct InnerVar<T>
where
    T: Clone,
{
    pub locked_thread_id: Option<AtomicUsize>,
    pub ctrl: Option<RLU<T>>,
    pub data: Arc<Mutex<T>>,
    pub copy: Option<Arc<Mutex<InnerVarCopy<T>>>>,
}

impl<T> InnerVar<T>
where
    T: Clone,
{
    /// Returns true, if this object is an original and references a copy
    pub(crate) fn is_locked(&self) -> bool {
        self.copy.is_some()
    }

    /// Returns true, if this object is an original and does not references a copy
    pub(crate) fn is_unlocked(&self) -> bool {
        self.copy.is_none()
    }

    pub fn get(&self) -> &T {
        // &self.data
        todo!()
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
            copy: None,
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
            copy: None,
        }
    }
}

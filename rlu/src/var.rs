// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Atomic, IntoRaw, RLU};
use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicPtr, AtomicUsize, Ordering},
        Arc,
    },
};

/// # RLUVar &lt;T&gt;
/// This type represents an rlu managed type. The type is is not being constructed directly
/// but with the help of [`RLU`].
pub struct RLUVar<T>
where
    T: Clone,
{
    pub(crate) inner: Arc<AtomicPtr<InnerVar<T>>>,
}

impl<T> RLUVar<T>
where
    T: Clone,
{
    /// This function returns the inner value, or None if the pointer is null
    pub fn get(&self) -> Option<&T> {
        match self.inner.load(Ordering::SeqCst) {
            ptr if ptr.is_null() => None,
            ptr => {
                let inner = unsafe { &*ptr };
                Some(&inner.data)
            }
        }
    }
    /// Swaps the inner variable with another
    ///
    /// # Safety
    /// This method is unsafe, as the pointer might be changed somewhere else and might not get tracked
    /// properly
    pub unsafe fn swap(&self, other: *mut InnerVar<T>) {
        self.inner.swap(other, Ordering::SeqCst);
    }
}

impl<T> Deref for RLUVar<T>
where
    T: Clone,
{
    type Target = InnerVar<T>;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> DerefMut for RLUVar<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> From<T> for RLUVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        RLUVar {
            inner: Arc::new(AtomicPtr::new(InnerVar::from(value).into_raw())),
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
    pub data: Atomic<T>,
    pub original: AtomicPtr<InnerVar<T>>,
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
            original: AtomicPtr::new(self.original.load(Ordering::SeqCst)),
        }
    }
}

pub struct InnerVar<T>
where
    T: Clone,
{
    pub locked_thread_id: Option<AtomicUsize>,
    pub ctrl: Option<RLU<T>>,
    pub(crate) data: Atomic<T>,

    pub copy: Option<AtomicPtr<InnerVarCopy<T>>>,
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
}

impl<T> From<T> for InnerVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        Self {
            data: Atomic::from(value),
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

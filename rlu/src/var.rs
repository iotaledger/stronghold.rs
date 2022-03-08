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
    /// This function returns the inner value.
    pub fn get(&self) -> &T {
        match unsafe { &*self.inner.load(Ordering::SeqCst) } {
            InnerVar::Copy { data, .. } | InnerVar::Original { data, .. } => data,
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

pub enum InnerVar<T>
where
    T: Clone,
{
    Original {
        locked_thread_id: Option<AtomicUsize>,
        ctrl: Option<RLU<T>>,
        data: Atomic<T>,

        copy: Option<AtomicPtr<Self>>,
    },

    Copy {
        locked_thread_id: Option<AtomicUsize>,
        ctrl: Option<RLU<T>>,
        data: Atomic<T>,

        original: AtomicPtr<Self>,
    },
}

impl<T> InnerVar<T>
where
    T: Clone,
{
    /// Returns true, if this object is an original and references a copy
    pub(crate) fn is_locked(&self) -> bool {
        if let Self::Original { copy, .. } = self {
            return copy.is_some();
        }
        false
    }

    /// Returns true, if this object is an original and does not references a copy
    pub(crate) fn is_unlocked(&self) -> bool {
        if let Self::Original { copy, .. } = self {
            return copy.is_none();
        }
        false
    }

    /// Returns true, if this is a copy
    pub(crate) fn is_copy(&self) -> bool {
        matches!(self, Self::Copy { .. })
    }
}

impl<T> From<T> for InnerVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        Self::Original {
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
        match self {
            Self::Copy {
                ctrl,
                data,
                locked_thread_id,
                original,
            } => Self::Copy {
                ctrl: ctrl.clone(),
                data: data.clone(),
                locked_thread_id: Some(AtomicUsize::new(match locked_thread_id {
                    Some(inner) => inner.load(Ordering::SeqCst),
                    None => 0,
                })),
                original: AtomicPtr::new(unsafe { &mut *original.load(Ordering::SeqCst) }),
            },
            Self::Original {
                copy,
                ctrl,
                data,
                locked_thread_id,
            } => Self::Original {
                copy: copy
                    .as_ref()
                    .map(|inner| AtomicPtr::new(unsafe { &mut *inner.load(Ordering::SeqCst) })),
                ctrl: ctrl.clone(),
                data: data.clone(),

                locked_thread_id: Some(AtomicUsize::new(match locked_thread_id {
                    Some(inner) => inner.load(Ordering::SeqCst),
                    None => 0,
                })),
            },
        }
    }
}

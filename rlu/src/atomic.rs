// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::IntoRaw;
use std::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicPtr, Ordering},
};

/// # Atomic &lt;T&gt;
///
/// Wrapper type for [`AtomicPtr`], but with extra heap allocation for the inner type.
///
/// ## Example
/// ```
/// use stronghold_rlu::rlu::Atomic;
/// let expected = 1024usize;
/// let atomic_usize = Atomic::from(expected);
/// assert_eq!(expected, *atomic_usize);
/// ```
pub struct Atomic<T>
where
    T: Clone,
{
    inner: AtomicPtr<T>,
}

impl<T> Atomic<T>
where
    T: Clone,
{
    /// Swaps the inner value and returns the old value.
    ///
    /// ## Safety
    /// This function is unsafe as it tries to dereference a raw pointer which must be allocated
    /// in accordance to the memory layout of a Box type.
    pub unsafe fn swap(&self, value: &mut T) -> T {
        let old = Box::from_raw(self.inner.swap(value, Ordering::SeqCst));
        *old
    }
}

impl<T> Deref for Atomic<T>
where
    T: Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> DerefMut for Atomic<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> From<T> for Atomic<T>
where
    T: Clone + IntoRaw,
{
    fn from(value: T) -> Self {
        Self {
            inner: AtomicPtr::new(value.into_raw()),
        }
    }
}

impl<T> Clone for Atomic<T>
where
    T: Clone,
{
    /// This creates and returns a copy of the pointer to the inner value, not a copy of the value itself
    fn clone(&self) -> Self {
        Self {
            inner: AtomicPtr::new(self.inner.load(Ordering::SeqCst)),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Atomic;
    use rand_utils::random::{string, usize};

    fn rand_string() -> String {
        string(255)
    }

    #[inline(always)]
    fn rand_usize() -> usize {
        usize(usize::MAX)
    }

    #[test]
    fn test_atomic_type() {
        let num_runs = 1000;

        for _ in 0..num_runs {
            let expected = rand_string();
            let mut expected_mod = expected.clone();
            expected_mod.push_str("_modified");

            let atomic_string = Atomic::from(expected.clone());
            assert_eq!(expected, *atomic_string);

            unsafe { atomic_string.swap(&mut expected_mod) };
            assert_eq!(expected_mod, *atomic_string);
        }
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{boxed::Boxed, types::*};

use core::{
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};

#[derive(Clone, Eq)]
pub struct Guarded<T: Bytes> {
    boxed: Boxed<T>,
}

pub struct Ref<'a, T: Bytes> {
    boxed: &'a Boxed<T>,
}

pub struct RefMut<'a, T: Bytes> {
    boxed: &'a mut Boxed<T>,
}

impl<T: Bytes> Guarded<T> {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        Self {
            boxed: Boxed::new(1, |b| f(b.as_mut())),
        }
    }

    pub fn try_new<R, E, F>(f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut T) -> Result<R, E>,
    {
        Boxed::try_new(1, |b| f(b.as_mut())).map(|b| Self { boxed: b })
    }

    pub fn size(&self) -> usize {
        self.boxed.size()
    }

    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::new(&self.boxed)
    }

    pub fn borrow_mut(&mut self) -> RefMut<'_, T> {
        RefMut::new(&mut self.boxed)
    }
}

impl<'a, T: Bytes> Ref<'a, T> {
    fn new(boxed: &'a Boxed<T>) -> Self {
        assert!(boxed.len() == 1, "Attempted to dereference a box with zero length");

        Self { boxed: boxed.unlock() }
    }
}

impl<T: Bytes> PartialEq for Ref<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<RefMut<'_, T>> for Ref<'_, T> {
    fn eq(&self, rhs: &RefMut<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for Ref<'_, T> {}

impl<'a, T: Bytes> RefMut<'a, T> {
    fn new(boxed: &'a mut Boxed<T>) -> Self {
        assert!(boxed.len() == 1, "Attempted to dereference a boxed with zero length");

        Self {
            boxed: boxed.unlock_mut(),
        }
    }
}

impl<T: Bytes> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self {
            boxed: self.boxed.unlock(),
        }
    }
}

impl<T: Bytes> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut()
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + Randomized> Guarded<T> {
    pub fn random() -> Self {
        Self {
            boxed: Boxed::random(1),
        }
    }
}

impl<T: Bytes + ZeroOut> Guarded<T> {
    pub fn zero() -> Self {
        Self { boxed: Boxed::zero(1) }
    }
}

impl<T: Bytes + ZeroOut> From<&mut T> for Guarded<T> {
    fn from(data: &mut T) -> Self {
        Self { boxed: data.into() }
    }
}

impl<T: Bytes> Debug for Guarded<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + ConstEq> PartialEq for Guarded<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<T: Bytes> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<Ref<'_, T>> for RefMut<'_, T> {
    fn eq(&self, rhs: &Ref<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for RefMut<'_, T> {}

unsafe impl<T: Bytes + Send> Send for Guarded<T> {}
unsafe impl<T: Bytes + Sync> Sync for Guarded<T> {}

#[cfg(test)]
mod test {
    extern crate alloc;

    use alloc::format;

    use super::*;

    #[test]
    fn test_init() {
        let _ = Guarded::<u64>::new(|v| {
            *v = 0x8f1a;

            assert_eq!(*v, 0x8f1a);
        });

        assert!(Guarded::<u8>::try_new(|_| Ok::<(), ()>(())).is_ok());
    }

    #[test]
    fn test_borrows() {
        let guarded = Guarded::<u64>::zero();
        let borrow = guarded.borrow();

        assert_eq!(*borrow, 0);

        let mut guarded = Guarded::<u64>::zero();
        let mut borrow = guarded.borrow_mut();

        *borrow = 0x01ab_cdef;

        assert_eq!(*borrow, 0x01ab_cdef);
    }

    #[test]
    fn test_arrays() {
        let guarded = Guarded::<[u8; 10]>::new(|v| *v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        assert_eq!(*guarded.borrow(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(guarded.size(), 10);

        let guarded = Guarded::<[u128; 4]>::zero();

        assert_eq!(guarded.size(), 64);
    }

    #[test]
    fn test_guard() {
        let mut guard = Guarded::<u64>::random();

        assert_eq!(format!("{{ size: {}, hidden }}", 8), format!("{:?}", guard),);

        assert_eq!(format!("{{ size: {}, hidden }}", 8), format!("{:?}", guard.borrow()),);

        assert_eq!(
            format!("{{ size: {}, hidden }}", 8),
            format!("{:?}", guard.borrow_mut()),
        );
    }

    #[test]
    fn test_moving_and_cloning() {
        let guard = Guarded::<u8>::zero();

        let moved = guard;

        assert_eq!(*moved.borrow(), 0);

        let guard = Guarded::<u8>::random();

        let borrow = guard.borrow();
        let clone = borrow.clone();

        assert_eq!(borrow, clone);
    }

    #[test]
    fn test_comparisons() {
        let guard = Guarded::<u8>::random();

        let clone = guard.clone();

        assert_eq!(guard, clone);

        let guard_a = Guarded::<[u128; 8]>::random();
        let guard_b = Guarded::<[u128; 8]>::random();

        assert_ne!(guard_a, guard_b);

        let mut guard = Guarded::<u8>::from(&mut 0xaf);
        let mut clone = guard.clone();

        assert_eq!(guard.borrow_mut(), clone.borrow_mut());
        assert_eq!(guard.borrow_mut(), clone.borrow());
    }

    #[test]
    #[should_panic]
    fn test_borrowing_zero_length() {
        let boxed = Boxed::<u8>::zero(0);
        let _ = boxed.as_ref();
    }

    #[test]
    #[should_panic]
    fn test_borrowing_zero_length_mut() {
        let mut boxed = Boxed::<u8>::zero(0);
        let _ = boxed.as_mut();
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{boxed::Boxed, types::*};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, SerializeSeq, Serializer},
};

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

/// A guarded type for protecting variable-length secrets allocated on the heap.
///
/// Provides the following features and guarantees:
/// * Causes segfault upon access without using a borrow.
/// * Protected using mprotect:
///    * `Prot::NoAccess` - when the box has no current borrows.
///    * `Prot::ReadOnly` - when the box has at least one current immutable borrow.
///    * `Prot::ReadWrite` - when the box has a current mutable borrow (can only have one at a time).
/// * The allocated memory uses guard pages both proceeding and following the memory. Overflows and large underflows
///   cause immediate termination of the program.
/// * A canary proceeds the memory location to detect smaller underflows.  The program will drop the underlying memory
///   and terminate if detected.
/// * The Memory is locked with `mlock`.
/// * When the memory is freed, `munlock` is called.
/// * The memory is zeroed when no longer in use via `sodium_free`.
/// * `Guarded` types can be compared in constant time.
/// * `Guarded` types can not be printed using `Debug`.
/// * The interior data of a `Guarded` type may not be `Clone`.
/// `GuardedVec` includes serialization which converts the data into a vector before its serialized by serde.  Upon
/// deserialization, the data is returned back to a new GuardedVec.

#[derive(Clone, Eq)]
pub struct GuardedVec<T: Bytes> {
    boxed: Boxed<T>,
}

pub struct Ref<'a, T: Bytes> {
    boxed: &'a Boxed<T>,
}

pub struct RefMut<'a, T: Bytes> {
    boxed: &'a mut Boxed<T>,
}

impl<T: Bytes> GuardedVec<T> {
    pub fn new<F>(len: usize, f: F) -> Self
    where
        F: FnOnce(&mut [T]),
    {
        Self {
            boxed: Boxed::new(len, |b| f(b.as_mut_slice())),
        }
    }

    pub fn try_new<U, E, F>(f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut [T]) -> Result<U, E>,
    {
        Boxed::try_new(1, |b| f(b.as_mut_slice())).map(|b| Self { boxed: b })
    }

    pub fn len(&self) -> usize {
        self.boxed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.boxed.is_empty()
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

impl<T: Bytes + Randomized> GuardedVec<T> {
    pub fn random(len: usize) -> Self {
        Self {
            boxed: Boxed::random(len),
        }
    }
}

impl<T: Bytes + Zeroed> GuardedVec<T> {
    pub fn zero(len: usize) -> Self {
        Self {
            boxed: Boxed::zero(len),
        }
    }
}

impl<T: Bytes + Zeroed> From<&mut [T]> for GuardedVec<T> {
    fn from(data: &mut [T]) -> Self {
        Self { boxed: data.into() }
    }
}

impl<T: Bytes> Debug for GuardedVec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + ConstEq> PartialEq for GuardedVec<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<'a, T: Bytes> Ref<'a, T> {
    fn new(boxed: &'a Boxed<T>) -> Self {
        Self { boxed: boxed.unlock() }
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
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_slice()
    }
}

impl<T: Bytes> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
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
        Self {
            boxed: boxed.unlock_mut(),
        }
    }
}

impl<T: Bytes> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_slice()
    }
}

impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut_slice()
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
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

unsafe impl<T: Bytes + Send> Send for GuardedVec<T> {}
unsafe impl<T: Bytes + Sync> Sync for GuardedVec<T> {}

impl<T: Bytes> Serialize for GuardedVec<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.len()))?;
        for e in self.borrow().iter() {
            state.serialize_element(e)?;
        }
        state.end()
    }
}

struct GuardedVecVisitor<T: Bytes> {
    marker: PhantomData<fn() -> GuardedVec<T>>,
}

impl<T: Bytes> GuardedVecVisitor<T> {
    fn new() -> Self {
        GuardedVecVisitor { marker: PhantomData }
    }
}

impl<'de, T: Bytes> Visitor<'de> for GuardedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = GuardedVec<T>;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("GuardedVec not found")
    }

    fn visit_seq<E>(self, mut access: E) -> Result<Self::Value, E::Error>
    where
        E: SeqAccess<'de>,
    {
        extern crate alloc;
        use alloc::vec::Vec;

        let mut seq = Vec::<T>::with_capacity(access.size_hint().unwrap_or(0));

        while let Some(e) = access.next_element()? {
            seq.push(e);
        }

        let seq = GuardedVec::new(seq.len(), |s| s.copy_from_slice(seq.as_slice()));

        Ok(seq)
    }
}

impl<'de, T: Bytes> Deserialize<'de> for GuardedVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(GuardedVecVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    use alloc::format;

    #[test]
    fn test_init() {
        let _ = GuardedVec::<u64>::new(6, |v| {
            v.clone_from_slice(&[1, 2, 3, 4, 5, 6][..]);

            assert_eq!(*v, [1, 2, 3, 4, 5, 6])
        });

        assert!(GuardedVec::<u8>::try_new(|_| Ok::<(), ()>(())).is_ok());
    }

    #[test]
    fn test_borrow() {
        let vec = GuardedVec::<u64>::zero(2);
        let v = vec.borrow();

        assert_eq!(*v, [0, 0]);

        let mut vec = GuardedVec::<u64>::zero(2);
        let mut v = vec.borrow_mut();

        v.clone_from_slice(&[7, 1][..]);

        assert_eq!(*v, [7, 1]);

        let vec = GuardedVec::<[u8; 2]>::new(2, |v| {
            v.clone_from_slice(&[[1, 2], [3, 4]][..]);
        });

        assert_eq!(*vec.borrow(), [[1, 2], [3, 4]]);
    }

    #[test]
    fn test_properties() {
        let vec = GuardedVec::<[u64; 4]>::zero(64);
        assert_eq!(vec.len(), 64);
        assert_eq!(vec.size(), 2048);
    }

    #[test]
    fn test_guard() {
        let mut guard = GuardedVec::<u64>::random(32);

        assert_eq!(format!("{{ size: {}, hidden }}", 256), format!("{:?}", guard),);

        assert_eq!(format!("{{ size: {}, hidden }}", 256), format!("{:?}", guard.borrow()),);

        assert_eq!(
            format!("{{ size: {}, hidden }}", 256),
            format!("{:?}", guard.borrow_mut()),
        );
    }

    #[test]
    fn test_moving_and_cloning() {
        let guard = GuardedVec::<u8>::zero(1);

        let moved = guard;

        assert_eq!(*moved.borrow(), [0]);

        let guard = GuardedVec::<u8>::random(8);

        let borrow = guard.borrow();
        let clone = borrow.clone();

        assert_eq!(borrow, clone);
    }

    #[test]
    fn test_comparisons() {
        let guard = GuardedVec::<u8>::from(&mut [1, 2, 3][..]);

        let clone = guard.clone();

        assert_eq!(guard, clone);

        let guard_a = GuardedVec::<[u128; 8]>::random(32);
        let guard_b = GuardedVec::<[u128; 8]>::random(32);

        assert_ne!(guard_a, guard_b);

        let mut guard = GuardedVec::<u8>::from(&mut [0xaf][..]);
        let mut clone = guard.clone();

        assert_eq!(guard.borrow_mut(), clone.borrow_mut());
        assert_eq!(guard.borrow_mut(), clone.borrow());
        assert_eq!(guard.borrow_mut(), clone.borrow());
        assert_eq!(guard.borrow(), clone.borrow_mut());
    }
}

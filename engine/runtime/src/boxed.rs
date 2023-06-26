// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::*;

use core::{
    cell::Cell,
    fmt::{self, Debug},
    mem,
    ptr::NonNull,
    slice,
};

use libsodium_sys::{
    sodium_allocarray, sodium_free, sodium_init, sodium_mlock, sodium_mprotect_noaccess, sodium_mprotect_readonly,
    sodium_mprotect_readwrite,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prot {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

type RefCount = u8;

/// A protected piece of memory.
#[derive(Eq)]
pub(crate) struct Boxed<T: Bytes> {
    // the pointer to the underlying protected memory
    ptr: NonNull<T>,
    // The number of elements of type `T` that can be stored in the pointer.
    len: usize,
    // the current protection level of the data.
    prot: Cell<Prot>,
    // The number of current borrows of this pointer.
    refs: Cell<RefCount>,
}

impl<T: Bytes> Boxed<T> {
    pub(crate) fn new<F>(len: usize, init: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        let mut boxed = Self::new_unlocked(len);
        unsafe { lock_memory(boxed.ptr.as_mut(), len) };

        assert!(
            boxed.ptr != core::ptr::NonNull::dangling(),
            "Make sure pointer isn't dangling"
        );
        assert!(boxed.len == len);

        init(&mut boxed);

        boxed.lock();

        boxed
    }

    pub(crate) fn try_new<R, E, F>(len: usize, init: F) -> Result<Self, E>
    where
        F: FnOnce(&mut Self) -> Result<R, E>,
    {
        let mut boxed = Self::new_unlocked(len);

        assert!(
            boxed.ptr != core::ptr::NonNull::dangling(),
            "Make sure pointer isn't dangling"
        );
        assert!(boxed.len == len);

        let res = init(&mut boxed);

        boxed.lock();

        res.map(|_| boxed)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn size(&self) -> usize {
        self.len * T::size()
    }

    pub(crate) fn unlock(&self) -> &Self {
        self.retain(Prot::ReadOnly);
        self
    }

    pub(crate) fn unlock_mut(&mut self) -> &mut Self {
        self.retain(Prot::ReadWrite);
        self
    }

    pub(crate) fn lock(&self) {
        self.release()
    }

    pub(crate) fn as_ref(&self) -> &T {
        assert!(!self.is_empty(), "Attempted to dereference a zero-length pointer");

        assert!(self.prot.get() != Prot::NoAccess, "May not call Boxed while locked");

        unsafe { self.ptr.as_ref() }
    }

    pub(crate) fn as_mut(&mut self) -> &mut T {
        assert!(!self.is_empty(), "Attempted to dereference a zero-length pointer");

        assert!(
            self.prot.get() == Prot::ReadWrite,
            "May not call Boxed unless mutably unlocked"
        );

        unsafe { self.ptr.as_mut() }
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        assert!(self.prot.get() != Prot::NoAccess, "May not call Boxed while locked");

        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        assert!(
            self.prot.get() == Prot::ReadWrite,
            "May not call Boxed unless mutably unlocked"
        );

        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    fn new_unlocked(len: usize) -> Self {
        if unsafe { sodium_init() == -1 } {
            panic!("Failed to initialize libsodium")
        }

        let ptr = NonNull::new(unsafe { sodium_allocarray(len, mem::size_of::<T>()) as *mut _ })
            .expect("Failed to allocate memory");

        Self {
            ptr,
            len,
            prot: Cell::new(Prot::ReadWrite),
            refs: Cell::new(1),
        }
    }

    fn retain(&self, prot: Prot) {
        let refs = self.refs.get();

        if refs == 0 {
            assert!(prot != Prot::NoAccess, "Must retain readably or writably");

            self.prot.set(prot);
            mprotect(self.ptr.as_ptr(), prot);
        } else {
            assert!(
                Prot::NoAccess != self.prot.get(),
                "Out-of-order retain/release detected"
            );
            assert!(
                Prot::ReadWrite != self.prot.get(),
                "Cannot unlock mutably more than once"
            );
            assert!(Prot::ReadOnly == prot, "Cannot unlock mutably while unlocked immutably");
        }

        match refs.checked_add(1) {
            Some(v) => self.refs.set(v),
            None if self.is_locked() => panic!("Out-of-order retain/release detected"),
            None => panic!("Retained too many times"),
        };
    }

    fn release(&self) {
        assert!(self.refs.get() != 0, "Releases exceeded retains");

        assert!(
            self.prot.get() != Prot::NoAccess,
            "Releasing memory that's already locked"
        );

        let refs = self.refs.get().wrapping_sub(1);

        self.refs.set(refs);

        if refs == 0 {
            mprotect(self.ptr.as_ptr(), Prot::NoAccess);
            self.prot.set(Prot::NoAccess);
        }
    }

    fn is_locked(&self) -> bool {
        self.prot.get() == Prot::NoAccess
    }
}

impl<T: Bytes + Randomized> Boxed<T> {
    pub(crate) fn random(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().randomize())
    }
}

impl<T: Bytes + Zeroed> Boxed<T> {
    pub(crate) fn zero(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().zero())
    }
}

impl<T: Bytes> Drop for Boxed<T> {
    fn drop(&mut self) {
        extern crate std;

        use std::thread;

        if !thread::panicking() {
            assert!(self.refs.get() == 0, "Retains exceeded releases");

            assert!(self.prot.get() == Prot::NoAccess, "Dropped secret was still accessible");
        }

        unsafe { free(self.ptr.as_mut()) }
    }
}

impl<T: Bytes> Debug for Boxed<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ size: {}, hidden }}", self.size())
    }
}

impl<T: Bytes> Clone for Boxed<T> {
    fn clone(&self) -> Self {
        Self::new(self.len, |b| {
            b.as_mut_slice().copy_from_slice(self.unlock().as_slice());
            self.lock();
        })
    }
}

impl<T: Bytes + ConstEq> PartialEq for Boxed<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let lhs = self.unlock().as_slice();
        let rhs = other.unlock().as_slice();

        let ret = lhs.const_eq(rhs);

        self.lock();
        other.lock();

        ret
    }
}

impl<T: Bytes + Zeroed> From<&mut T> for Boxed<T> {
    fn from(data: &mut T) -> Self {
        Self::new(1, |b| unsafe { data.copy_and_zero(b.as_mut()) })
    }
}

impl<T: Bytes + Zeroed> From<&mut [T]> for Boxed<T> {
    fn from(data: &mut [T]) -> Self {
        Self::new(data.len(), |b| unsafe { data.copy_and_zero(b.as_mut_slice()) })
    }
}

unsafe impl<T: Bytes + Send> Send for Boxed<T> {}
unsafe impl<T: Bytes + Sync> Sync for Boxed<T> {}

fn mprotect<T>(ptr: *mut T, prot: Prot) {
    if !match prot {
        Prot::NoAccess => unsafe { sodium_mprotect_noaccess(ptr as *mut _) == 0 },
        Prot::ReadOnly => unsafe { sodium_mprotect_readonly(ptr as *mut _) == 0 },
        Prot::ReadWrite => unsafe { sodium_mprotect_readwrite(ptr as *mut _) == 0 },
    } {
        panic!("Error setting memory protection to {:?}", prot);
    }
}

pub(crate) unsafe fn free<T>(ptr: *mut T) {
    sodium_free(ptr as *mut _)
}

pub(crate) unsafe fn lock_memory<T>(ptr: *mut T, len: usize) {
    sodium_mlock(ptr as *mut _, len);
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use alloc::vec;

    use super::*;
    use libsodium_sys::randombytes_buf;

    #[test]
    fn test_init_with_garbage() {
        let boxed = Boxed::<u8>::new(4, |_| {});
        let unboxed = boxed.unlock().as_slice();

        let garbage = unsafe {
            let garb_ptr = sodium_allocarray(1, mem::size_of::<u8>()) as *mut u8;
            let garb_byte = *garb_ptr;

            free(garb_ptr);

            vec![garb_byte; unboxed.len()]
        };

        assert_ne!(garbage, vec![0; garbage.len()]);
        assert_eq!(unboxed, &garbage[..]);

        boxed.lock();
    }

    #[test]
    fn test_custom_init() {
        let boxed = Boxed::<u8>::new(1, |secret| {
            secret.as_mut_slice().copy_from_slice(b"\x04");
        });

        assert_eq!(boxed.unlock().as_slice(), [0x04]);
        boxed.lock();
    }

    #[test]
    fn test_init_with_zero() {
        let boxed = Boxed::<u8>::zero(6);

        assert_eq!(boxed.unlock().as_slice(), [0, 0, 0, 0, 0, 0]);

        boxed.lock();
    }

    #[test]
    fn test_init_with_values() {
        let mut value = [8u64];
        let boxed = Boxed::from(&mut value[..]);

        assert_eq!(value, [0]);
        assert_eq!(boxed.unlock().as_slice(), [8]);

        boxed.lock();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_eq() {
        let boxed_a = Boxed::<u8>::random(1);
        let boxed_b = boxed_a.clone();

        assert_eq!(boxed_a, boxed_b);
        assert_eq!(boxed_b, boxed_a);

        let boxed_a = Boxed::<u8>::random(16);
        let boxed_b = Boxed::<u8>::random(16);

        assert_ne!(boxed_a, boxed_b);
        assert_ne!(boxed_b, boxed_a);

        let boxed_b = Boxed::<u8>::random(12);

        assert_ne!(boxed_a, boxed_b);
        assert_ne!(boxed_b, boxed_a);
    }

    #[test]
    fn test_refs() {
        let mut boxed = Boxed::<u8>::zero(8);

        assert_eq!(0, boxed.refs.get());

        let _ = boxed.unlock();
        let _ = boxed.unlock();

        assert_eq!(2, boxed.refs.get());

        boxed.lock();
        boxed.lock();

        assert_eq!(0, boxed.refs.get());

        let _ = boxed.unlock_mut();

        assert_eq!(1, boxed.refs.get());

        boxed.lock();

        assert_eq!(0, boxed.refs.get());
    }

    #[test]
    fn test_ref_overflow() {
        let boxed = Boxed::<u8>::zero(8);

        for _ in 0..u8::max_value() {
            let _ = boxed.unlock();
        }

        for _ in 0..u8::max_value() {
            boxed.lock()
        }
    }

    #[test]
    fn test_random_borrow_amounts() {
        let boxed = Boxed::<u8>::zero(1);
        let mut counter = 0u8;

        unsafe {
            randombytes_buf(
                counter.as_mut_bytes().as_mut_ptr() as *mut _,
                counter.as_mut_bytes().len(),
            );
        }

        for _ in 0..counter {
            let _ = boxed.unlock();
        }

        for _ in 0..counter {
            boxed.lock()
        }
    }

    #[test]
    fn test_threading() {
        extern crate std;

        use std::{sync::mpsc, thread};

        let (tx, rx) = mpsc::channel();

        let ch = thread::spawn(move || {
            let boxed = Boxed::<u64>::random(1);
            let val = boxed.unlock().as_slice().to_vec();

            tx.send((boxed, val)).expect("failed to send via channel");
        });

        let (boxed, val) = rx.recv().expect("failed to read from channel");

        assert_eq!(Prot::ReadOnly, boxed.prot.get());
        assert_eq!(val, boxed.as_slice());

        ch.join().expect("child thread terminated.");
        boxed.lock();
    }

    #[test]
    #[should_panic(expected = "Retained too many times")]
    fn test_overflow_refs() {
        let boxed = Boxed::<[u8; 4]>::zero(4);

        for _ in 0..=u8::max_value() {
            let _ = boxed.unlock();
        }

        for _ in 0..boxed.refs.get() {
            boxed.lock()
        }
    }

    #[test]
    #[should_panic(expected = "Out-of-order retain/release detected")]
    fn test_out_of_order() {
        let boxed = Boxed::<u8>::zero(3);

        boxed.refs.set(boxed.refs.get().wrapping_sub(1));
        boxed.prot.set(Prot::NoAccess);

        boxed.retain(Prot::ReadOnly);
    }

    #[test]
    #[should_panic(expected = "Attempted to dereference a zero-length pointer")]
    fn test_zero_length() {
        let boxed = Boxed::<u8>::zero(0);

        let _ = boxed.as_ref();
    }

    #[test]
    #[should_panic(expected = "Cannot unlock mutably more than once")]
    fn test_multiple_writers() {
        let mut boxed = Boxed::<u64>::zero(1);

        let _ = boxed.unlock_mut();
        let _ = boxed.unlock_mut();
    }

    #[test]
    #[should_panic(expected = "Releases exceeded retains")]
    fn test_release_vs_retain() {
        Boxed::<u64>::zero(2).lock();
    }
}

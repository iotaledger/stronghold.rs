// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{sodium::*, types::*};

use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};

/// A Type for guarding secrets allocated to the stack.
///
/// Provides the following security features and guarentees:
/// * The Memory is locked with [`mlock`].
/// * When the memory is freed, [`munlock`] is called.
/// * the memory is zeroed out when no longer in use.
/// * values are compared in constant time.
/// * values are prevented from being Debugged.
/// * Values can not be cloned.

pub struct Secret<T: Bytes> {
    /// Internally protected data for the [`Secret`].
    data: T,
}

/// A mutable [`Deref`] wrapper around the [`Secret`]'s internal data. Intercepts calls to [`Clone`] and [`Debug`] the
/// data in the secret.
pub struct RefMut<'a, T: Bytes> {
    /// a reference to the underlying secret data that will be derefed
    data: &'a mut T,
}

impl<T: Bytes> Secret<T> {
    /// Creates a new [`Secret`] and invokes the provided callback with
    /// a wrapper to the protected memory.
    ///
    /// ```
    /// # use runtime::Secret;
    /// let sec = [0u8, 1u8];
    /// // Wraps the sec data in a secret.
    /// Secret::<[u8; 2]>::new(|mut s| {
    ///    s.copy_from_slice(&sec[..]);
    //     assert_eq!(*s, [0u8, 1u8]);
    /// });
    ///
    /// ```
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::new_ret_no_self))]
    pub fn new<F, A>(f: F) -> A
    where
        F: FnOnce(RefMut<'_, T>) -> A,
    {
        let mut secret = Self {
            data: T::uninitialized(),
        };

        if unsafe { !mlock(&mut secret.data) } {
            panic!("Unable to mlock memory for secret!");
        };

        f(RefMut::new(&mut secret.data))
    }
}

impl<T: Bytes + Zeroed> Secret<T> {
    /// Creates a new [`Secret`] filled with zeroed bytes and invokes the
    /// callback with a wrapper to the protected memory.
    ///
    /// ```
    /// # use runtime::Secret;
    /// Secret::<u8>::zero(|s| {
    ///     assert_eq!(*s, 0);
    /// });
    /// ```
    pub fn zero<F, A>(f: F) -> A
    where
        F: FnOnce(RefMut<'_, T>) -> A,
    {
        Self::new(|mut s| {
            s.zero();
            f(s)
        })
    }

    /// Creates a new [`Secret`] from existing, unprotected data, and
    /// immediately zeroes out the memory of the data being moved in.
    /// ```
    /// # use runtime::Secret;
    /// let mut value = [1u8, 2u8];
    ///
    /// // the contents of `value` will be copied into the Secret before
    /// // being zeroed out
    /// Secret::from(&mut value, |s| {
    ///     assert_eq!(*s, [1, 2]);
    /// });
    ///
    /// // the contents of `value` have been zeroed
    /// assert_eq!(value, [0, 0]);
    /// ```
    pub fn from<F, A>(v: &mut T, f: F) -> A
    where
        F: FnOnce(RefMut<'_, T>) -> A,
    {
        Self::new(|mut s| {
            unsafe { v.copy_and_zero(s.borrow_mut()) };
            f(s)
        })
    }
}

impl<T: Bytes + Randomized> Secret<T> {
    /// Creates a new [`Secret`] filled with random bytes and invokes
    /// the callback with a wrapper to the protected memory.
    ///
    /// ```
    /// # use runtime::Secret;
    /// Secret::<u128>::random(|s| {
    ///     // s is filled with random bytes
    /// })
    /// ```
    pub fn random<F, U>(f: F) -> U
    where
        F: FnOnce(RefMut<'_, T>) -> U,
    {
        Self::new(|mut s| {
            s.randomize();
            f(s)
        })
    }
}

impl<T: Bytes> Drop for Secret<T> {
    /// Ensures that the [`Secret`]'s underlying memory is `munlock`ed
    /// and zeroed when it leaves scope.
    fn drop(&mut self) {
        unsafe {
            munlock(&mut self.data);
        }
    }
}

impl<'a, T: Bytes> RefMut<'a, T> {
    /// Creates a new `RefMut`.
    pub(crate) fn new(data: &'a mut T) -> Self {
        Self { data }
    }
}

impl<T: Bytes + Clone> Clone for RefMut<'_, T> {
    fn clone(&self) -> Self {
        panic!("May not be clone a Secret")
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ size: {}, hidden }}", self.data.size())
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}
impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: Bytes> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.data.const_eq(rhs.data)
    }
}

impl<T: Bytes> Eq for RefMut<'_, T> {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::format;

    // pub(crate) fn memrandom(bytes: &mut [u8]) {
    //     unsafe { randombytes_buf(bytes.as_mut_ptr() as *mut _, bytes.len()) }
    // }

    #[test]
    fn test_default() {
        Secret::<u8>::new(|s| assert_eq!(*s, 0xdb));
        Secret::<u16>::new(|s| assert_eq!(*s, 0xdbdb));
        Secret::<u32>::new(|s| assert_eq!(*s, 0xdbdbdbdb));
    }

    // #[test]
    // fn test_zeroed() {
    //     // Bit of a hack but works.
    //     unsafe {
    //         let mut ptr: *const _ = ptr::null();

    //         Secret::<u128>::new(|mut s| {
    //             memrandom(s.as_mut_bytes());

    //             ptr = &*s
    //         });

    //         assert_eq!(*ptr, 0);
    //     }
    // }

    #[test]
    fn test_from() {
        Secret::from(&mut 5, |s| assert_eq!(*s, 5_u8));

        let mut value = 5_u8;

        Secret::from(&mut value, |_| {});

        assert_eq!(value, 0);
    }

    #[test]
    fn test_comparisons() {
        Secret::<u32>::from(&mut 0x01234567, |a| {
            Secret::<u32>::from(&mut 0x01234567, |b| {
                assert_eq!(a, b);
            });
        });

        Secret::<[u64; 4]>::random(|a| {
            Secret::<[u64; 4]>::random(|b| {
                assert_ne!(a, b);
            });
        });
    }

    #[test]
    fn test_secret() {
        Secret::<[u32; 2]>::zero(|s| {
            assert_eq!(format!("{{ size: {}, hidden }}", 8), format!("{:?}", s),);
        })
    }

    #[test]
    #[should_panic]
    fn test_clone() {
        Secret::<u8>::zero(|s| {
            let _ = s.clone();
        })
    }
}

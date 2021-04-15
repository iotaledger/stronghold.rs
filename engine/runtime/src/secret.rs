use crate::{sodium::*, types::*};

use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};

pub struct Secret<T: Bytes> {
    data: T,
}

pub struct RefMut<'a, T: Bytes> {
    data: &'a mut T,
}

impl<T: Bytes> Secret<T> {
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
    pub fn zero<F, A>(f: F) -> A
    where
        F: FnOnce(RefMut<'_, T>) -> A,
    {
        Self::new(|mut s| {
            s.zero();
            f(s)
        })
    }

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
    fn drop(&mut self) {
        unsafe {
            munlock(&mut self.data);
        }
    }
}

impl<'a, T: Bytes> RefMut<'a, T> {
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

    use std::{format, ptr};

    use libsodium_sys::randombytes_buf;

    pub(crate) fn memrandom(bytes: &mut [u8]) {
        unsafe { randombytes_buf(bytes.as_mut_ptr() as *mut _, bytes.len()) }
    }

    #[test]
    fn test_default() {
        Secret::<u8>::new(|s| assert_eq!(*s, 0xdb));
        Secret::<u16>::new(|s| assert_eq!(*s, 0xdbdb));
        Secret::<u32>::new(|s| assert_eq!(*s, 0xdbdbdbdb));
    }

    #[test]
    fn test_zeroed() {
        unsafe {
            let mut ptr: *const _ = ptr::null();

            Secret::<u128>::new(|mut s| {
                memrandom(s.as_mut_bytes());

                ptr = &*s
            });

            assert_eq!(*ptr, 0);
        }
    }

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

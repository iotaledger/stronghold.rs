// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::mem::GuardedAllocation;

use core::{
    alloc::Layout,
    cell::Cell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

struct GuardedCell {
    alloc: GuardedAllocation,
    readers: Cell<usize>,
    writers: Cell<usize>,
}

impl GuardedCell {
    fn new(l: Layout) -> crate::Result<Self> {
        let alloc = GuardedAllocation::aligned(l)?;
        alloc.protect(false, false)?;
        Ok(Self {
            alloc,
            readers: Cell::new(0),
            writers: Cell::new(0),
        })
    }

    fn with_ptr<T, F: FnOnce(*const u8) -> T>(&self, f: F) -> crate::Result<T> {
        self.add_reader()?;
        let t = f(self.alloc.data());
        self.remove(true, false)?;
        Ok(t)
    }

    fn with_mut_ptr<T, F: FnOnce(*mut u8) -> T>(&self, f: F) -> crate::Result<T> {
        self.add_reader()?;
        self.add_writer()?;
        let t = f(self.alloc.data());
        self.remove(true, true)?;
        Ok(t)
    }

    fn add_reader(&self) -> crate::Result<()> {
        let r = self.readers.get();
        if r == 0 {
            self.alloc.protect(true, 0 < self.writers.get())?;
        }
        self.readers.set(r + 1);

        Ok(())
    }

    fn add_writer(&self) -> crate::Result<()> {
        let w = self.writers.get();
        if w == 0 {
            self.alloc.protect(0 < self.readers.get(), true)?;
        }
        self.writers.set(w + 1);

        Ok(())
    }

    fn remove(&self, read: bool, write: bool) -> crate::Result<()> {
        let r = if read {
            let r = self.readers.get();
            self.readers.set(r - 1);
            r - 1
        } else {
            self.readers.get()
        };

        let w = if write {
            let w = self.writers.get();
            self.writers.set(w - 1);
            w - 1
        } else {
            self.writers.get()
        };

        self.alloc.protect(r > 0, w > 0)
    }

    fn access(&self) -> GuardedCellAccess {
        GuardedCellAccess {
            inner: self,
            read: Cell::new(false),
            write: Cell::new(false),
        }
    }
}

impl Drop for GuardedCell {
    fn drop(&mut self) {
        self.alloc.protect(false, true).unwrap();
        self.alloc.free().unwrap();
    }
}

struct GuardedCellAccess<'a> {
    inner: &'a GuardedCell,
    read: Cell<bool>,
    write: Cell<bool>,
}

impl GuardedCellAccess<'_> {
    fn read(&self) -> *const u8 {
        if !self.read.get() {
            self.inner.add_reader().unwrap();
            self.read.set(true);
        }

        self.inner.alloc.data()
    }

    fn write(&self) -> *mut u8 {
        if !self.write.get() {
            self.inner.add_writer().unwrap();
            self.write.set(true);
        }

        self.inner.alloc.data()
    }
}

impl Drop for GuardedCellAccess<'_> {
    fn drop(&mut self) {
        let r = self.read.get();
        let w = self.write.get();
        if r || w {
            self.inner.remove(r, w).unwrap();
        }
    }
}

pub mod vec {
    use super::*;

    pub struct GuardedVec<A> {
        inner: GuardedCell,
        n: usize,
        a: PhantomData<A>,
    }

    impl<A: Copy> GuardedVec<A> {
        pub fn copy(a: &[A]) -> crate::Result<Self> {
            let n = a.len();
            let l = Layout::array::<A>(n).map_err(crate::mem::Error::Layout)?;
            let inner = GuardedCell::new(l)?;

            let gv = Self {
                inner,
                n,
                a: PhantomData,
            };
            (*gv.access()).copy_from_slice(a);

            Ok(gv)
        }
    }

    impl<A: Clone> GuardedVec<A> {
        pub fn clone(a: &[A]) -> crate::Result<Self> {
            let n = a.len();
            let l = Layout::array::<A>(n).map_err(crate::mem::Error::Layout)?;
            let inner = GuardedCell::new(l)?;

            inner.with_mut_ptr(|p| {
                let p = p as *mut A;

                for (i, a) in a.iter().enumerate() {
                    unsafe {
                        p.add(i).write(a.clone());
                    }
                }
            })?;

            Ok(Self {
                inner,
                n,
                a: PhantomData,
            })
        }
    }

    impl<A> GuardedVec<A> {
        pub fn access(&self) -> GuardedVecAccess<A> {
            GuardedVecAccess {
                inner: self.inner.access(),
                n: self.n,
                a: PhantomData,
            }
        }
    }

    impl<A> Drop for GuardedVec<A> {
        fn drop(&mut self) {
            if core::mem::needs_drop::<A>() {
                self.inner.alloc.protect(true, true).unwrap();
                let p = self.inner.alloc.data() as *mut A;
                for i in 0..self.n {
                    unsafe {
                        p.add(i).drop_in_place();
                    }
                }
            }
        }
    }

    pub struct GuardedVecAccess<'a, A> {
        inner: GuardedCellAccess<'a>,
        n: usize,
        a: PhantomData<A>,
    }

    impl<A> Deref for GuardedVecAccess<'_, A> {
        type Target = [A];

        fn deref(&self) -> &[A] {
            let p = self.inner.read() as *const A;

            unsafe { core::slice::from_raw_parts(p, self.n) }
        }
    }

    impl<A> DerefMut for GuardedVecAccess<'_, A> {
        fn deref_mut(&mut self) -> &mut [A] {
            let p = self.inner.write() as *mut A;

            unsafe { core::slice::from_raw_parts_mut(p, self.n) }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn copy() -> crate::Result<()> {
            let gv = GuardedVec::copy(&[1, 2, 3])?;
            assert_eq!(*gv.access(), [1, 2, 3]);
            gv.access()[0] = 4;
            gv.access()[1] = 5;
            gv.access()[2] = 6;
            assert_eq!(*gv.access(), [4, 5, 6]);
            Ok(())
        }

        #[test]
        fn clone() -> crate::Result<()> {
            let gv = GuardedVec::clone(&[1, 2, 3])?;
            assert_eq!(*gv.access(), [1, 2, 3]);
            gv.access()[0] = 4;
            gv.access()[1] = 5;
            gv.access()[2] = 6;
            assert_eq!(*gv.access(), [4, 5, 6]);
            Ok(())
        }

        #[test]
        fn drop() -> crate::Result<()> {
            struct Droplet<'a> {
                clones: &'a Cell<usize>,
            }

            impl Clone for Droplet<'_> {
                fn clone(&self) -> Self {
                    self.clones.set(self.clones.get() + 1);
                    Self { clones: self.clones }
                }
            }

            impl Drop for Droplet<'_> {
                fn drop(&mut self) {
                    self.clones.set(self.clones.get() - 1);
                }
            }

            let cs = Cell::new(1);

            {
                let _gv = GuardedVec::clone(&[Droplet { clones: &cs }]);
                assert_eq!(cs.get(), 1);
            }

            assert_eq!(cs.get(), 0);

            Ok(())
        }
    }
}

pub mod r#box {
    use super::*;

    pub struct GuardedBox<A> {
        inner: GuardedCell,
        a: PhantomData<A>,
    }

    impl<A> GuardedBox<A> {
        pub fn new(a: A) -> crate::Result<Self> {
            let l = Layout::new::<A>();
            let inner = GuardedCell::new(l)?;
            inner.with_mut_ptr(|p| {
                let p = p as *mut A;
                // NB no need to run forget(a) since write takes ownership
                unsafe {
                    p.write(a);
                }
            })?;

            Ok(Self { inner, a: PhantomData })
        }

        pub fn access(&self) -> GuardedBoxAccess<A> {
            GuardedBoxAccess {
                inner: self.inner.access(),
                a: PhantomData,
            }
        }
    }

    impl<A> Drop for GuardedBox<A> {
        fn drop(&mut self) {
            if core::mem::needs_drop::<A>() {
                self.inner
                    .with_mut_ptr(|p| unsafe {
                        (p as *mut A).drop_in_place();
                    })
                    .unwrap();
            }
        }
    }

    pub struct GuardedBoxAccess<'a, A> {
        inner: GuardedCellAccess<'a>,
        a: PhantomData<A>,
    }

    impl<A> Deref for GuardedBoxAccess<'_, A> {
        type Target = A;

        fn deref(&self) -> &A {
            let p = self.inner.read() as *const A;

            unsafe {
                // TODO: do we actually have any guarantees that mmap can't return a valid mapping at
                // the NULL pointer?
                p.as_ref().unwrap()
            }
        }
    }

    impl<A> DerefMut for GuardedBoxAccess<'_, A> {
        fn deref_mut(&mut self) -> &mut A {
            let p = self.inner.write() as *mut A;

            unsafe {
                // TODO: do we actually have any guarantees that mmap can't return a valid mapping at
                // the NULL pointer?
                p.as_mut().unwrap()
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn access() -> crate::Result<()> {
            let gb = GuardedBox::new(7)?;
            assert_eq!(*gb.access(), 7);
            *gb.access() = 8;
            assert_eq!(*gb.access(), 8);
            Ok(())
        }

        #[test]
        fn drop() -> crate::Result<()> {
            struct Droplet<'a> {
                dropped: &'a Cell<bool>,
            }

            impl Drop for Droplet<'_> {
                fn drop(&mut self) {
                    self.dropped.set(true);
                }
            }

            let b = Cell::new(false);

            {
                let _gb = GuardedBox::new(Droplet { dropped: &b });
                assert_eq!(b.get(), false);
            }

            assert_eq!(b.get(), true);

            Ok(())
        }
    }
}

pub mod string {
    use super::{
        vec::{GuardedVec, GuardedVecAccess},
        *,
    };

    pub struct GuardedString {
        inner: GuardedVec<u8>,
        n: usize,
    }

    impl GuardedString {
        pub fn new(s: &str) -> crate::Result<Self> {
            Ok(Self {
                inner: GuardedVec::copy(s.as_bytes())?,
                n: s.len(),
            })
        }

        pub fn len(&self) -> usize {
            self.n
        }

        pub fn is_empty(&self) -> bool {
            self.n == 0
        }

        pub fn access(&self) -> GuardedStringAccess {
            GuardedStringAccess {
                inner: self.inner.access(),
            }
        }
    }

    pub struct GuardedStringAccess<'a> {
        inner: GuardedVecAccess<'a, u8>,
    }

    impl Deref for GuardedStringAccess<'_> {
        type Target = str;

        fn deref(&self) -> &str {
            unsafe { core::str::from_utf8_unchecked(&self.inner) }
        }
    }

    impl DerefMut for GuardedStringAccess<'_> {
        fn deref_mut(&mut self) -> &mut str {
            unsafe { core::str::from_utf8_unchecked_mut(&mut self.inner) }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn new() -> crate::Result<()> {
            let gs = GuardedString::new("foo")?;
            assert_eq!(*gs.access(), *"foo");

            (*gs.access()).get_mut(..).map(|s| {
                s.make_ascii_uppercase();
                &*s
            });

            assert_eq!(*gs.access(), *"FOO");

            Ok(())
        }
    }
}

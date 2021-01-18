// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    cell::Cell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr,
};

use crate::secret::{AccessSelf, Protection, ProtectionNew};

use zeroize::Zeroize;

#[cfg(unix)]
mod posix;

#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use self::posix::{lock, mmap, munmap, page_size, prot, protect};

#[cfg(windows)]
pub use self::windows::{lock, mmap, munmap, page_size, prot, protect};

#[derive(PartialEq, Debug)]
pub enum Error {
    ZeroAllocation,
    Layout(LayoutErr),
}

fn pad(x: usize, n: usize) -> usize {
    match x % n {
        0 => 0,
        r => n - r,
    }
}

fn pad_minimizer(a: usize, b: usize, c: usize) -> usize {
    match b % c {
        0 => 0,
        bc => {
            if bc % a == 0 {
                c / a - bc / a
            } else {
                c / a - bc / a - 1
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct GuardedAllocation {
    base: *mut u8,
    data_region_start: *mut u8,
    data_region_size: usize,
    data_aligned: *mut u8,
    mmapped_size: usize, // size of the memory mapping (including guard pages)
}

impl GuardedAllocation {
    pub fn unaligned(n: usize) -> crate::Result<Self> {
        Self::aligned(Layout::from_size_align(n, 1).map_err(Error::Layout)?)
    }

    pub fn aligned(l: Layout) -> crate::Result<Self> {
        let n = l.size();
        if n == 0 {
            return Err(Error::ZeroAllocation.into());
        }

        let a = l.align();
        let p = page_size();

        let data_region_size = n + pad(n, p);
        let a = if p % a == 0 {
            let mmapped_size = p + data_region_size + p;
            let base = mmap(mmapped_size)?;
            let i = pad_minimizer(a, n, p);
            Self {
                base,
                data_region_start: unsafe { base.add(p) },
                data_region_size,
                data_aligned: unsafe { base.add(p + i * a) },
                mmapped_size,
            }
        } else if a % p == 0 {
            let x = mmap(a + data_region_size + p)?;
            let i = a / p;
            let j = x as usize / p;
            let o = i - 1 - (j % i);
            let base = unsafe { x.add(o * p) };
            if o > 0 {
                munmap(x, o * p)?;
            }
            let mmapped_size = p + n + pad(n, p) + p;

            if j % i > 0 {
                let end = unsafe { base.add(mmapped_size) };
                munmap(end, (j % i) * p)?;
            }

            Self {
                base,
                data_region_start: unsafe { base.add(p) },
                data_region_size,
                data_aligned: unsafe { base.add(p) },
                mmapped_size,
            }
        } else {
            return Err(crate::Error::unreachable(
                "page size and requested alignment is coprime",
            ));
        };

        a.protect(true, true)?;
        a.lock()?;

        Ok(a)

        // TODO: write canary for the writable page (NB don't write canaries in the guards,
        // then at least they don't reserve physical memory, (assuming COW))
    }

    unsafe fn from_ptr(data: *mut u8, l: Layout) -> Self {
        let p = page_size();
        let n = l.size();
        let data_region_size = n + pad(n, p);
        let mmapped_size = p + data_region_size + p;
        let base = data.offset(-((p + (data as usize) % p) as isize));
        Self {
            base,
            data_region_start: base.add(p),
            data_region_size,
            data_aligned: data,
            mmapped_size,
        }
    }

    pub fn free(&self) -> crate::Result<()> {
        unsafe { core::slice::from_raw_parts_mut(self.data_region_start, self.data_region_size) }.zeroize();
        munmap(self.base, self.mmapped_size)
    }

    pub fn data(&self) -> *mut u8 {
        self.data_aligned
    }

    fn protect(&self, read: bool, write: bool) -> crate::Result<()> {
        let prot = prot(read, write);
        protect(self.data_region_start, self.data_region_size, prot)
    }

    fn lock(&self) -> crate::Result<()> {
        lock(self.data_region_start, self.data_region_size)
    }
}

pub struct GuardedBox<A> {
    alloc: GuardedAllocation,
    a: PhantomData<A>,
    readers: Cell<usize>,
    writers: Cell<usize>,
}

impl<A> GuardedBox<A> {
    pub fn new(a: A) -> crate::Result<Self> {
        let l = Layout::new::<A>();
        let alloc = GuardedAllocation::aligned(l)?;
        // NB no need to run forget(a) since write takes ownership
        unsafe { (alloc.data() as *mut A).write(a) }
        alloc.protect(false, false)?;
        Ok(Self {
            alloc,
            a: PhantomData,
            readers: Cell::new(0),
            writers: Cell::new(0),
        })
    }

    pub fn uninit() -> crate::Result<Self> {
        let l = Layout::new::<A>();
        let alloc = GuardedAllocation::aligned(l)?;
        alloc.protect(false, false)?;
        Ok(Self {
            alloc,
            a: PhantomData,
            readers: Cell::new(0),
            writers: Cell::new(0),
        })
    }

    pub fn with_ptr<T, F: FnOnce(*const A) -> T>(&self, f: F) -> crate::Result<T> {
        self.add_reader()?;
        let t = f(self.alloc.data() as *const A);
        self.remove(true, false)?;
        Ok(t)
    }

    pub fn with_mut_ptr<T, F: FnOnce(*mut A) -> T>(&self, f: F) -> crate::Result<T> {
        self.add_reader()?;
        self.add_writer()?;
        let t = f(self.alloc.data() as *mut A);
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
}

impl<A> Drop for GuardedBox<A> {
    fn drop(&mut self) {
        if core::mem::needs_drop::<A>() {
            self.alloc.protect(true, true).unwrap();
            unsafe {
                (self.alloc.data() as *mut A).drop_in_place();
            }
        } else {
            self.alloc.protect(false, true).unwrap();
        }

        self.alloc.free().unwrap();
    }
}

impl<A> Protection<A> for GuardedBox<A> {
    type AtRest = Self;
}

impl<A> ProtectionNew<A> for GuardedBox<A> {
    fn protect(a: A) -> crate::Result<Self::AtRest> {
        GuardedBox::new(a)
    }
}

pub struct GuardedBoxAccess<'a, A> {
    inner: &'a GuardedBox<A>,
    read: Cell<bool>,
    write: Cell<bool>,
}

impl<A> Deref for GuardedBoxAccess<'_, A> {
    type Target = A;

    fn deref(&self) -> &A {
        if !self.read.get() {
            self.inner.add_reader().unwrap();
            self.read.set(true);
        }

        unsafe {
            // TODO: do we actually have any guarantees that mmap can't return a valid mapping at
            // the NULL pointer?
            (self.inner.alloc.data() as *const A).as_ref().unwrap()
        }
    }
}

impl<A> DerefMut for GuardedBoxAccess<'_, A> {
    fn deref_mut(&mut self) -> &mut A {
        if !self.write.get() {
            self.inner.add_writer().unwrap();
            self.write.set(true);
        }

        unsafe {
            // TODO: do we actually have any guarantees that mmap can't return a valid mapping at
            // the NULL pointer?
            (self.inner.alloc.data() as *mut A).as_mut().unwrap()
        }
    }
}

impl<'a, A> Drop for GuardedBoxAccess<'a, A> {
    fn drop(&mut self) {
        let r = self.read.get();
        let w = self.write.get();
        if r || w {
            self.inner.remove(r, w).unwrap();
        }
    }
}

impl<'a, A: 'a> AccessSelf<'a, A> for GuardedBox<A> {
    type Accessor = GuardedBoxAccess<'a, A>;

    fn access(&'a self) -> crate::Result<Self::Accessor> {
        Ok(GuardedBoxAccess {
            inner: &self,
            read: Cell::new(false),
            write: Cell::new(false),
        })
    }
}

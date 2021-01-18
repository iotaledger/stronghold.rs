// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    cell::Cell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

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

// TODO: figure out the correct name, "Cell" isn't really it?
struct GuardedCell {
    alloc: GuardedAllocation,
    readers: Cell<usize>,
    writers: Cell<usize>,
}

impl GuardedCell {
    pub fn new(l: Layout) -> crate::Result<Self> {
        let alloc = GuardedAllocation::aligned(l)?;
        alloc.protect(false, false)?;
        Ok(Self {
            alloc,
            readers: Cell::new(0),
            writers: Cell::new(0),
        })
    }

    pub fn with_ptr<T, F: FnOnce(*const u8) -> T>(&self, f: F) -> crate::Result<T> {
        self.add_reader()?;
        let t = f(self.alloc.data());
        self.remove(true, false)?;
        Ok(t)
    }

    pub fn with_mut_ptr<T, F: FnOnce(*mut u8) -> T>(&self, f: F) -> crate::Result<T> {
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

    pub fn access<'a>(&'a self) -> GuardedCellAccess<'a> {
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

pub struct GuardedCellAccess<'a> {
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

pub struct GuardedVec<A> {
    inner: GuardedCell,
    n: usize,
    a: PhantomData<A>,
}

impl<A: Copy> GuardedVec<A> {
    pub fn copy(a: &[A]) -> crate::Result<Self> {
        let n = a.len();
        let l = Layout::array::<A>(n).map_err(|e| Error::Layout(e))?;
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
        let l = Layout::array::<A>(n).map_err(|e| Error::Layout(e))?;
        let inner = GuardedCell::new(l)?;

        inner.with_mut_ptr(|p| {
            let p = p as *mut A;

            for i in 0..n {
                unsafe {
                    p.add(i).write(a[i].clone());
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
    pub fn access<'a>(&'a self) -> GuardedVecAccess<'a, A> {
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
mod guarded_vec_tests {
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

    pub fn access<'a>(&'a self) -> GuardedBoxAccess<A> {
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
mod guarded_box_tests {
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

    pub fn access<'a>(&'a self) -> GuardedStringAccess<'a> {
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
mod guarded_string_tests {
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

pub struct GuardedAllocator {}

impl GuardedAllocator {
    pub const fn new() -> Self {
        Self {}
    }
}

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        GuardedAllocation::aligned(l).map(|a| a.data()).unwrap()
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        GuardedAllocation::from_ptr(p, l).free().unwrap()
    }
}

#[cfg(feature = "stdalloc")]
pub mod stdalloc {
    use super::*;
    use core::cell::Cell;

    struct Toggleable<A, B> {
        a: A,
        b: B,
    }

    impl<A, B> Toggleable<A, B> {
        const fn new(a: A, b: B) -> Self {
            Self { a, b }
        }
    }

    unsafe impl<A: GlobalAlloc, B: GlobalAlloc> GlobalAlloc for Toggleable<A, B> {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            T.with(|t| match t.get() {
                false => self.a.alloc(l),
                true => self.b.alloc(l),
            })
        }

        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            T.with(|t| match t.get() {
                false => self.a.dealloc(p, l),
                true => self.b.dealloc(p, l),
            })
        }
    }

    thread_local! {
        static T: Cell<bool> = Cell::new(false);
    }

    #[global_allocator]
    static ALLOC: Toggleable<std::alloc::System, GuardedAllocator> =
        Toggleable::new(std::alloc::System, GuardedAllocator::new());

    /// Use the standad allocator from this point on in the current thread
    ///
    /// # Safety
    /// If the allocator used to allocate memory is not enabled when deallocation occurs the
    /// behavior is undefined. Hopefully the process will get killed with a SIGSEGV. It is
    /// recommended to switch allocators early and late in a process'/thread's lifetime.
    pub unsafe fn std() {
        T.with(|t| t.set(false));
    }

    /// Use the guarded allocator from this point on in the current thread
    ///
    /// # Safety
    /// If the allocator used to allocate memory is not enabled when deallocation occurs the
    /// behavior is undefined. Hopefully the process will get killed with a SIGSEGV. It is
    /// recommended to switch allocators early and late in a process'/thread's lifetime.
    pub unsafe fn guarded() {
        T.with(|t| t.set(true));
    }
}

#[cfg(target_os = "linux")]
pub fn seccomp_spec() -> crate::seccomp::Spec {
    crate::seccomp::Spec {
        anonymous_mmap: true,
        munmap: true,
        mprotect: true,
        mlock: true,
        ..crate::seccomp::Spec::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, Rng};

    #[cfg(target_os = "linux")]
    const MEM_ACCESS_ERR: crate::Error = crate::Error::ZoneError(crate::zone::Error::Signal { signo: libc::SIGSEGV });
    #[cfg(target_os = "macos")]
    const MEM_ACCESS_ERR: crate::Error = crate::Error::ZoneError(crate::zone::Error::Signal { signo: libc::SIGBUS });

    #[cfg(not(feature = "stdalloc"))]
    #[global_allocator]
    static ALLOC: GuardedAllocator = GuardedAllocator::new();

    #[cfg(not(feature = "stdalloc"))]
    fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
        f()
    }

    #[cfg(feature = "stdalloc")]
    fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
        unsafe { stdalloc::guarded() };
        let a = f();
        unsafe { stdalloc::std() };
        a
    }

    fn page_size_exponent() -> u32 {
        let mut p = 1;
        let mut k = 0;
        while p != page_size() {
            p *= 2;
            k += 1;
        }
        k as u32
    }

    fn fresh_non_zero_size(bound: usize) -> usize {
        let mut n = 0;
        while n == 0 {
            n = OsRng.gen::<usize>() % bound;
        }
        n
    }

    fn fresh_layout() -> Layout {
        let n = fresh_non_zero_size(3 * page_size());
        let a = 2usize.pow(OsRng.gen::<u32>() % page_size_exponent() + 3);
        Layout::from_size_align(n, a).unwrap()
    }

    fn do_test_write(p: *mut u8, n: usize) {
        let bs = unsafe { core::slice::from_raw_parts_mut(p, n) };
        for b in bs.iter() {
            assert_eq!(*b, 0u8);
        }

        OsRng.fill(bs);
    }

    fn do_sized_alloc_test(n: usize) -> crate::Result<()> {
        let a = GuardedAllocation::unaligned(n)?;

        do_test_write(a.data(), n);

        a.free()?;

        Ok(())
    }

    #[test]
    fn allocate_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(page_size())
    }

    #[test]
    fn allocate_less_than_a_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(1)
    }

    #[test]
    fn allocate_little_more_than_a_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(page_size() + 1)
    }

    #[test]
    fn allocate_random_sizes() -> crate::Result<()> {
        for _ in 1..10 {
            do_sized_alloc_test(fresh_non_zero_size(1024 * 1024))?
        }
        Ok(())
    }

    #[test]
    fn alignment() -> crate::Result<()> {
        for _ in 1..100 {
            let l = fresh_layout();
            let a = GuardedAllocation::aligned(l)?;
            assert_eq!((a.data() as usize) % l.align(), 0);
            do_test_write(a.data(), l.size());
            a.free()?;
        }

        Ok(())
    }

    #[test]
    fn zero_allocation() -> crate::Result<()> {
        assert_eq!(GuardedAllocation::unaligned(0), Err(Error::ZeroAllocation.into()),);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn guard_pages_pre_read() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        assert_eq!(0u8, core::ptr::read_unaligned(a.data().offset(-(i as isize))));
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn guard_pages_pre_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().offset(-(i as isize)), OsRng.gen());
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn guard_pages_post_read() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        assert_eq!(0u8, core::ptr::read_unaligned(a.data().add(l.size() + i)));
                    };
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn guard_pages_post_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().add(l.size() + i), OsRng.gen());
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    fn vectors() -> crate::Result<()> {
        with_guarded_allocator(|| {
            extern crate alloc;
            use alloc::vec::Vec;

            let mut bs: Vec<u8> = Vec::with_capacity(10);
            for _ in 1..100 {
                bs.push(OsRng.gen());
            }

            Ok(())
        })
    }

    // TODO: unify these apis, maybe a dedicated zone::Spec?
    #[test]
    #[cfg(target_os = "linux")]
    fn inside_zone_linux() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::fork(|| {
            seccomp_spec().with_getrandom().apply().unwrap();
            let a = GuardedAllocation::aligned(l).unwrap();
            do_test_write(a.data(), l.size());
            a.free().unwrap();
        })
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn inside_zone_macos() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::fork(|| {
            let a = GuardedAllocation::aligned(l).unwrap();
            do_test_write(a.data(), l.size());
            a.free().unwrap();
        })
    }
}

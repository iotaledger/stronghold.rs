// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This module implements a memory allocator, that fragments two or more parts
//! of requested memory. There are some strategies to fragment multiple parts of memory.
//! The most simple approach is to allocate memory multiple times, return the final allocation
//! as the desired memory.
//!
//! Allocators differ between operating systems. On *nix and BSD-based systems `malloc(int)` is being called
//! but does not initialize the allocated spaced. Microsoft Windows uses
//! [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
//! allocates and initializes a region of memory pages with zeroes.
//!
//! [`FragStrategy`] implements at least two possible allocation strategies:
//!
//! - Default: The algorithm tries to allocate a huge amount of memory space while keeping a certain address distance
//! - Memory Mapped: anonymous memory is being mapping, the memory address will be randomly selected.

use crate::MemoryError;
use std::{fmt::Debug, mem::MaybeUninit, ptr::NonNull};

/// Fragmenting strategy to allocate memory at random addresses.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FragStrategy {
    /// Anonymously maps a region of memory
    MMap,

    /// System's allocator will be called a few times
    Direct,
}

// -----------------------------------------------------------------------------

/// Custom allocator trait
pub trait Alloc<T> {
    type Error;

    /// Allocates `T`, returns an error if something wrong happened
    fn alloc() -> Result<NonNull<T>, Self::Error>;
}

// -----------------------------------------------------------------------------

/// Frag is being used as control object to load different allocators
/// according to their strategy
pub struct Frag;

impl Frag {
    /// Returns a fragmenting allocator by strategy
    ///
    /// # Example
    ///
    /// ```skip
    /// use stronghold_engine::runtime::memories::*;
    ///
    /// let object  = Frag::by_strategy(FragStrategy::Default).unwrap();
    /// ```
    fn alloc_single<T>(s: FragStrategy) -> Result<NonNull<T>, MemoryError>
    where
        T: Default,
    {
        match s {
            FragStrategy::Direct => DirectAlloc::alloc(),
            FragStrategy::MMap => MemoryMapAlloc::alloc(),
        }
    }

    /// Tries to allocate two objects of the same type with a minimum distance in memory space.
    pub fn alloc2<T>(strategy: FragStrategy, distance: usize) -> Option<(NonNull<T>, NonNull<T>)>
    where
        T: Default,
    {
        let d = |a: &T, b: &T| {
            let a = a as *const T as usize;
            let b = b as *const T as usize;

            a.abs_diff(b)
        };

        let a = Self::alloc_single::<T>(strategy).ok()?;
        let b = Self::alloc_single::<T>(strategy).ok()?;
        unsafe {
            if d(a.as_ref(), b.as_ref()) < distance {
                return None;
            }
        }

        Some((a, b))
    }
    /// Tries to allocate two objects of the same type with a default minimum distance in memory space of `0xFFFF`.
    pub fn alloc<T>(strategy: FragStrategy) -> Option<(NonNull<T>, NonNull<T>)>
    where
        T: Default,
    {
        Self::alloc2(strategy, 0xFFFF)
    }
}

// -----------------------------------------------------------------------------

#[derive(Default, Clone)]
struct ForkAlloc;

impl<T> Alloc<T> for ForkAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(target_os = "windows")]
    fn alloc() -> Result<T, Self::Error> {
        todo!()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        let mut pipe = [-1_i32; 2];
        let piped_result = unsafe { libc::pipe(&mut pipe as *mut i32) };

        if piped_result < 0 {
            return Err(MemoryError::Allocation("Failed to create pipe".to_string()));
        }

        // child process
        let pid;
        unsafe {
            pid = libc::fork();

            match pid {
                0 => {
                    std::panic::set_hook(Box::new(|_| {
                        libc::exit(0);
                    }));

                    // ptrace hook
                    // libc::ptrace(libc::PTRACE_TRACEME);

                    // todo: register error hooks
                    // allocate memory and free it immediately
                    // (0..10).for_each(|_| {
                    // MaybeUninit::<[u8; usize::MAX >> 45]>::uninit().as_mut_ptr();
                    // });

                    let mut ptr = libc::malloc(usize::MAX);
                    let mut i: usize = 0;
                    while ptr.is_null() {
                        ptr = libc::malloc(usize::MAX >> i);
                        i = i.saturating_add(1);
                    }

                    println!("a got allocated at {:p}", ptr);

                    let mut ptr = libc::malloc(usize::MAX);
                    let mut i: usize = 0;
                    while ptr.is_null() {
                        ptr = libc::malloc(usize::MAX >> i);
                        i = i.saturating_add(1);
                    }
                    println!("b got allocated at {:p}", ptr);
                    libc::free(ptr);

                    libc::dup2(pipe[1], 1); // map write to stdout
                    libc::close(pipe[0]);

                    let mut object = T::default();
                    let ptr = &mut object as *mut T as *mut u8;
                    let mut size = std::mem::size_of::<T>();

                    while size > 0 {
                        let w = libc::write(1, ptr as *const libc::c_void, size);
                        if w < 0 {
                            return Err(MemoryError::Allocation("Failed to send allocated memory".to_string()));
                        }

                        size -= w as usize;
                    }

                    libc::_exit(0);
                }
                _ if pid < 0 => {
                    return Err(MemoryError::Allocation("Failed to fork process".to_string()));
                }

                _ => {
                    println!("Got child pid: {}", pid);
                }
            };
        }

        unsafe {
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);

            match status {
                _ if libc::WIFEXITED(status) => {
                    if libc::WIFSTOPPED(status) {
                        return Err(MemoryError::Allocation("Child process crash".to_string()));
                    }

                    // read from pipe
                    let mut m: MaybeUninit<T> = MaybeUninit::uninit();
                    let mut size = std::mem::size_of::<T>();
                    let p = m.as_mut_ptr();
                    println!("Reading from pipe");
                    while size > 0 {
                        let read = libc::read(pipe[0], p as *mut libc::c_void, size);
                        if read < 0 {
                            return Err(MemoryError::Allocation("Failed to read from pipe".to_string()));
                        }

                        size -= read as usize;
                    }

                    Ok(NonNull::new_unchecked(p))
                }
                _ => Err(MemoryError::Allocation(
                    "Unknown state while waiting for child process".to_string(),
                )),
            }
        }
    }
}

// -----------------------------------------------------------------------------

#[derive(Default, Clone)]
struct MemoryMapAlloc;

impl<T> Alloc<T> for MemoryMapAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        let size = std::mem::size_of::<T>();

        use random::{thread_rng, Rng};
        let mut rng = thread_rng();

        unsafe {
            loop {
                let mut addr: usize = rng.gen::<usize>();

                let ptr = libc::mmap(
                    &mut addr as *mut usize as *mut libc::c_void,
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                    -1,
                    0,
                );

                if ptr == libc::MAP_FAILED {
                    continue;
                }

                // on linux this isn't required to commit memory
                // libc::madvise(&mut addr as *mut usize as *mut libc::c_void, size, libc::MADV_WILLNEED);

                let ptr = ptr as *mut T;

                if !ptr.is_null() {
                    let t = T::default();
                    ptr.write(t);

                    return Ok(NonNull::new_unchecked(ptr));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn alloc() -> Result<T, Self::Error> {
        todo!()
    }
}

// -----------------------------------------------------------------------------

/// [`DirectAlloc`] tries to allocate a "huge" block of memory randomly,
/// resizing the chunk to the desired size of the to be allocated object.
///
/// The actual implementation is system dependent and might vary.
///
/// # Example
/// ```
/// use stronghold_engine::runtime::memories::frag::{Frag, FragStrategy};
///
/// // allocates the object at a random address
/// let object = Frag::<usize>alloc().unwrap();
/// ```
#[derive(Default, Clone)]
struct DirectAlloc;

impl<T> Alloc<T> for DirectAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        use random::{thread_rng, Rng};

        let mut rng = thread_rng();
        loop {
            unsafe {
                let alloc_size = rng.gen::<usize>() >> 32;
                let mem_ptr = libc::malloc(alloc_size);
                if mem_ptr.is_null() {
                    continue;
                }
                let actual_size = std::mem::size_of::<T>();
                let actual_mem = libc::realloc(mem_ptr, actual_size) as *mut T;
                actual_mem.write(T::default());

                return Ok(NonNull::new_unchecked(actual_mem));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn alloc() -> Result<T, Self::Error> {
        todo!()
    }
}

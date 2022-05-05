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
use std::{fmt::Debug, ptr::NonNull};

/// Fragmenting strategy to allocate memory at random addresses.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FragStrategy {
    /// Anonymously maps a region of memory
    Map,

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
    pub fn alloc_single<T>(s: FragStrategy) -> Result<NonNull<T>, MemoryError>
    where
        T: Default,
    {
        match s {
            FragStrategy::Direct => DirectAlloc::alloc(),
            FragStrategy::Map => MemoryMapAlloc::alloc(),
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
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        todo!()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        use std::mem::MaybeUninit;

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
                #[cfg(any(target_os = "macos"))]
                libc::madvise(&mut addr as *mut usize as *mut libc::c_void, size, libc::MADV_WILLNEED);

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
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        use random::{thread_rng, Rng};
        let mut rng = thread_rng();

        let handle = windows::Win32::Foundation::INVALID_HANDLE_VALUE;

        unsafe {
            // allocation prelude
            {
                let r_addr = rng.gen::<u32>() >> 4;

                let random_mapping = windows::Win32::System::Memory::CreateFileMappingW(
                    handle,
                    std::ptr::null_mut(),
                    windows::Win32::System::Memory::PAGE_READWRITE,
                    0,
                    r_addr,
                    windows::core::PCWSTR(std::ptr::null_mut()),
                )
                .map_err(|e| MemoryError::Allocation(e.to_string()))?;

                if let Err(e) = last_error() {
                    return Err(e);
                }

                let _ = windows::Win32::System::Memory::MapViewOfFile(
                    random_mapping,
                    windows::Win32::System::Memory::FILE_MAP_ALL_ACCESS,
                    0,
                    0,
                    r_addr as usize,
                );

                if let Err(e) = last_error() {
                    return Err(e);
                }
            }

            // actual memory mapping
            {
                let actual_size = std::mem::size_of::<T>() as u32;
                let actual_mapping = windows::Win32::System::Memory::CreateFileMappingW(
                    handle,
                    std::ptr::null_mut(),
                    windows::Win32::System::Memory::PAGE_READWRITE,
                    0,
                    actual_size,
                    windows::core::PCWSTR(std::ptr::null_mut()),
                )
                .map_err(|e| MemoryError::Allocation(e.to_string()))?;

                if let Err(e) = last_error() {
                    return Err(e);
                }

                let actual_mem = windows::Win32::System::Memory::MapViewOfFile(
                    actual_mapping,
                    windows::Win32::System::Memory::FILE_MAP_ALL_ACCESS,
                    0,
                    0,
                    actual_size as usize,
                ) as *mut T;

                if let Err(e) = last_error() {
                    return Err(e);
                }

                actual_mem.write(T::default());

                return Ok(NonNull::new_unchecked(actual_mem as *mut T));
            }
        }
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
/// use runtime::memories::frag::{Frag, FragStrategy};
///
/// // allocates the object at a random address
/// let object = Frag::alloc::<usize>(FragStrategy::Direct).unwrap();
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
    fn alloc() -> Result<NonNull<T>, Self::Error> {
        loop {
            unsafe {
                let actual_size = std::mem::size_of::<T>();

                let actual_mem = windows::Win32::System::Memory::VirtualAlloc(
                    std::ptr::null_mut(),
                    actual_size,
                    windows::Win32::System::Memory::MEM_COMMIT | windows::Win32::System::Memory::MEM_RESERVE,
                    windows::Win32::System::Memory::PAGE_READWRITE,
                );

                if actual_mem.is_null() {
                    if let Err(_) = last_error() {
                        continue;
                    }
                }

                let actual_mem = actual_mem as *mut T;
                actual_mem.write(T::default());
                return Ok(NonNull::new_unchecked(actual_mem));
            };
        }
    }
}

// -----------------------------------------------------------------------------

/// Rounds `value` up to a multiple of `base`
///
/// # Example
/// ```
/// let n = 13;
/// let b = 14;
/// let c = runtime::memories::frag::round_up(n, b);
/// assert_eq!(c, 14);
/// ```
pub fn round_up(value: usize, base: usize) -> usize {
    if base == 0 {
        return value;
    }

    match value % base {
        0 => value,
        remainder => value + base - remainder,
    }
}

/// Checks for error codes under Windows.
///
/// Detected errors will be returned as [`MemoryError`]. If no error has been
/// detected eg. the function result is `0`, `Ok` will be returned.
#[cfg(target_os = "windows")]
fn last_error() -> Result<(), MemoryError> {
    unsafe {
        match windows::Win32::Foundation::GetLastError() {
            windows::Win32::Foundation::WIN32_ERROR(0) => Ok(()),
            windows::Win32::Foundation::ERROR_ALREADY_EXISTS => {
                Err(MemoryError::Allocation("Mapping already exists".to_owned()))
            }
            windows::Win32::Foundation::ERROR_INVALID_HANDLE => {
                Err(MemoryError::Allocation("Invalid handle for mapped memory".to_owned()))
            }
            windows::Win32::Foundation::ERROR_COMMITMENT_LIMIT => Err(MemoryError::Allocation(
                "The paging file is too small for this operation to complete".to_owned(),
            )),
            windows::Win32::Foundation::ERROR_INVALID_PARAMETER => {
                Err(MemoryError::Allocation("The parameter is incorrect.".to_owned()))
            }
            windows::Win32::Foundation::ERROR_INVALID_ADDRESS => {
                Err(MemoryError::Allocation("Attempt to access invalid address.".to_owned()))
            }
            err => Err(MemoryError::Allocation(format!("Unknown error code 0x{:08x}", err.0))),
        }
    }
}

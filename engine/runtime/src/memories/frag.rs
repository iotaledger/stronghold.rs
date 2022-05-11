// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This module provides functionality to allocate memory with higher randomness on returned addresses.
//!
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
//! - Direct: The algorithm tries to allocate a huge amount of memory space while keeping a certain address distance
//! - Memory Mapped: anonymous memory is being mapping, the memory address will be randomly selected.

use crate::MemoryError;
use log::*;
use std::{fmt::Debug, ptr::NonNull};

/// Fragmenting strategy to allocate memory at random addresses.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FragStrategy {
    /// Anonymously maps a region of memory
    Map,

    /// Using system allocator (`malloc` on linux/bsd/macos and `VirtualAlloc` on windows)
    Direct,
}

// -----------------------------------------------------------------------------

/// Custom allocator trait
pub trait Alloc<T> {
    type Error;

    /// Allocates `T`, returns an error if something wrong happened. Takes an
    /// optional configuration to check against a previous allocation
    fn alloc(config: Option<FragConfig>) -> Result<NonNull<T>, Self::Error>;
}

// -----------------------------------------------------------------------------

/// Frag is being used as control object to load different allocators
/// according to their strategy
pub struct Frag;

/// Configuration for the fragmenting allocator
pub struct FragConfig {
    /// The last address of a previous allocation. This
    /// value will be used to calculate the minimum distance to the
    /// previous allocation.
    pub(crate) last_address: usize,

    /// The  minimum distance to a previous allocation
    pub(crate) min_distance: usize,
}

impl FragConfig {
    /// Creates a new [`FragConfig`]
    pub fn new(last_address: usize, min_distance: usize) -> Self {
        Self {
            last_address,
            min_distance,
        }
    }
}

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
    pub fn alloc_single<T>(strategy: FragStrategy, config: Option<FragConfig>) -> Result<NonNull<T>, MemoryError>
    where
        T: Default,
    {
        match strategy {
            FragStrategy::Direct => DirectAlloc::alloc(config),
            FragStrategy::Map => MemoryMapAlloc::alloc(config),
        }
    }

    /// Tries to allocate two objects of the same type with a minimum distance in memory space.
    pub fn alloc2<T>(strategy: FragStrategy, distance: usize) -> Result<(NonNull<T>, NonNull<T>), MemoryError>
    where
        T: Default,
    {
        let a = Self::alloc_single::<T>(strategy, None)?;
        let b = Self::alloc_single::<T>(strategy, Some(FragConfig::new(&a as *const _ as usize, distance)))?;
        unsafe {
            let actual_distance = calc_distance(a.as_ref(), b.as_ref());
            if actual_distance < distance {
                return Err(MemoryError::Allocation(format!(
                    "Distance between parts below threshold: 0x{:016X}",
                    actual_distance
                )));
            }
        }

        Ok((a, b))
    }
    /// Tries to allocate two objects of the same type with a default minimum distance in memory space of `0xFFFF`.
    pub fn alloc<T>(strategy: FragStrategy) -> Result<(NonNull<T>, NonNull<T>), MemoryError>
    where
        T: Default,
    {
        Self::alloc2(strategy, 0xFFFF)
    }
}

// -----------------------------------------------------------------------------

/// [`MemoryMapAlloc`] maps an anonymous file with an arbitrary large size. Parts
/// of this memory will be randomly seeded.
///
/// The actual implementation is system dependent and might vary.
///
/// # Example
/// ```
/// use runtime::memories::frag::{Frag, FragStrategy};
///
/// // allocates the object at a random address
/// let object = Frag::alloc::<usize>(FragStrategy::Map).unwrap();
/// ```
#[derive(Default, Clone)]
struct MemoryMapAlloc;

impl<T> Alloc<T> for MemoryMapAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc(config: Option<FragConfig>) -> Result<NonNull<T>, Self::Error> {
        let hr = "-".repeat(20);
        info!("{0}Mapping Allocator{0}", hr);

        let size = std::mem::size_of::<T>();

        use random::{thread_rng, Rng};
        let mut rng = thread_rng();

        let default_page_size = 0x1000i64;

        let pagesize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .unwrap_or(Some(default_page_size))
            .unwrap() as usize;

        info!("Using page size {}", pagesize);

        unsafe {
            loop {
                let mut addr: usize = (rng.gen::<usize>() >> 32) & (!0usize ^ (pagesize - 1));

                info!("Desired addr  0x{:08X}", addr);

                // the maximum size of the mapping
                let max_alloc_size = 0xFFFFFF;

                let desired_alloc_size: usize = rng.gen_range(size..=max_alloc_size);

                info!("prealloc: desired alloc size 0x{:08X}", desired_alloc_size);

                // this creates an anonymous mapping zeroed out.
                let ptr = libc::mmap(
                    &mut addr as *mut _ as *mut libc::c_void,
                    desired_alloc_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                    -1,
                    0,
                );

                info!("Preallocated segment addr: {:p}", ptr);

                if ptr == libc::MAP_FAILED {
                    warn!("Memory mapping failed");
                    continue;
                }

                if let Some(ref cfg) = config {
                    let actual_distance = (ptr as usize).abs_diff(cfg.last_address);
                    if actual_distance < cfg.min_distance {
                        warn!("New allocation distance to previous allocation is below threshold.");
                        continue;
                    }
                }

                #[cfg(any(target_os = "macos"))]
                {
                    // on linux this isn't required to commit memory
                    let error = libc::madvise(&mut addr as *mut usize as *mut libc::c_void, size, libc::MADV_WILLNEED);

                    {
                        if error != 0 {
                            error!("madvise returned an error {}", error);
                            continue;
                        }
                    }
                }

                let ptr = ptr as *mut T;

                if !ptr.is_null() {
                    let t = T::default();
                    ptr.write(t);

                    info!("Object succesfully written into mem location");

                    return Ok(NonNull::new_unchecked(ptr));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn alloc(config: Option<FragConfig>) -> Result<NonNull<T>, Self::Error> {
        use random::{thread_rng, Rng};
        let mut rng = thread_rng();

        let handle = windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        loop {
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

                    if let Some(ref cfg) = config {
                        let actual_distance = (&*random_mapping as *const _ as usize).abs_diff(cfg.last_address);
                        if actual_distance < cfg.min_distance {
                            warn!("New allocation distance to previous allocation is below threshold.");

                            // remove previous file mapping
                            windows::Win32::System::Memory::UnmapViewOfFile(random_mapping);

                            if let Err(e) = last_error() {
                                return Err(e);
                            }

                            continue;
                        }
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
    fn alloc(config: Option<FragConfig>) -> Result<NonNull<T>, Self::Error> {
        use random::{thread_rng, Rng};

        let actual_size = std::mem::size_of::<T>();
        let mut rng = thread_rng();

        let min = 0xFFFF;
        let max = 0xFFFF_FFFF;

        // pick a default, if system api call is not successful
        let default_page_size = 0x1000i64;

        #[cfg(any(target_os = "unix", target_os = "linux"))]
        let _pagesize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .unwrap_or(Some(default_page_size))
            .unwrap() as usize;

        // Within the loop we allocate a sufficiently "large" chunk of memory. A random
        // offset will be added to the returned pointer and the object will be written. This
        // actually leaks memory.
        loop {
            unsafe {
                let mem_ptr = {
                    let alloc_size = rng.gen::<usize>().min(min).max(max);

                    // allocate some randomly sized chunk of memory
                    let ptr = libc::malloc(alloc_size);
                    if ptr.is_null() {
                        continue;
                    }

                    #[cfg(target_os = "macos")]
                    {
                        // on linux it isn't required to commit memory
                        let error = libc::madvise(ptr, actual_size, libc::MADV_WILLNEED);
                        if error != 0 {
                            error!("memory advise returned an error {}", error);
                            continue;
                        }
                    }

                    ptr
                };

                if let Some(ref cfg) = config {
                    let actual_distance = (mem_ptr as usize).abs_diff(cfg.last_address);
                    if actual_distance < cfg.min_distance {
                        warn!("New allocation distance to previous allocation is below threshold.");
                        continue;
                    }
                }

                // we are searching for some address in between
                let offset = rng.gen::<usize>().min(max - actual_size);
                let actual_mem = ((mem_ptr as usize) + offset) as *mut T;
                actual_mem.write(T::default());

                return Ok(NonNull::new_unchecked(actual_mem));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn alloc(config: Option<FragConfig>) -> Result<NonNull<T>, Self::Error> {
        use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

        loop {
            unsafe {
                let actual_size = std::mem::size_of::<T>();

                let actual_mem = VirtualAlloc(
                    std::ptr::null_mut(),
                    actual_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );

                if actual_mem.is_null() {
                    if let Err(_) = last_error() {
                        continue;
                    }
                }

                if let Some(ref cfg) = config {
                    let actual_distance = (actual_mem as usize).abs_diff(cfg.last_address);
                    if actual_distance < cfg.min_distance {
                        warn!("New allocation distance to previous allocation is below threshold.");
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
#[inline(always)]
pub fn round_up(value: usize, base: usize) -> usize {
    if base == 0 {
        return value;
    }

    match value % base {
        0 => value,
        remainder => value + base - remainder,
    }
}

/// Calulates the distance between two pointers and returns it
fn calc_distance<T>(a: &T, b: &T) -> usize {
    let a = a as *const T as usize;
    let b = b as *const T as usize;

    a.abs_diff(b)
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

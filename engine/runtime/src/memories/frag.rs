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
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

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
pub trait Alloc<T: Default> {
    type Error;

    /// Allocates `T`, returns an error if something wrong happened. Takes an
    /// optional configuration to check against a previous allocation
    fn alloc(config: Option<FragConfig>) -> Result<Frag<T>, Self::Error>;

    /// Deallocate `T`, returns an error if something wrong happened.
    fn dealloc(frag: Frag<T>) -> Result<(), Self::Error>;
}

// -----------------------------------------------------------------------------

/// Frag is being used as control object to load different allocators
/// according to their strategy
pub struct Frag<T: Default> {
    ptr: NonNull<T>,
    strategy: FragStrategy,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    info: (*mut libc::c_void, usize),

    #[cfg(target_os = "windows")]
    info: Option<(windows::Win32::Foundation::HANDLE, *const libc::c_void)>,
}

impl<T: Default> Deref for Frag<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Default> DerefMut for Frag<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

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

impl<T: Default> Frag<T> {
    /// Returns a fragmenting allocator by strategy
    ///
    /// # Example
    ///
    /// ```skip
    /// use stronghold_engine::runtime::memories::*;
    ///
    /// let object  = Frag::by_strategy(FragStrategy::Default).unwrap();
    /// ```

    pub fn alloc_single(strategy: FragStrategy, config: Option<FragConfig>) -> Result<Frag<T>, MemoryError> {
        match strategy {
            FragStrategy::Direct => DirectAlloc::alloc(config),
            FragStrategy::Map => MemoryMapAlloc::alloc(config),
        }
    }

    /// Tries to allocate two objects of the same type with a minimum distance in memory space.
    pub fn alloc2(strategy: FragStrategy, distance: usize) -> Result<(Frag<T>, Frag<T>), MemoryError> {
        let a = Self::alloc_single(strategy, None)?;
        let b = Self::alloc_single(strategy, Some(FragConfig::new(a.ptr.as_ptr() as usize, distance)))?;

        let actual_distance = calc_distance(&*a, &*b);
        if actual_distance < distance {
            error!(
                "Distance between parts below threshold: \nthreshold: 0x{:016X} \nactual_distance: 0x{:016X}",
                distance, actual_distance
            );
            error!(
                "Distance between parts below threshold: \na: 0x{:016x} \nb: 0x{:016x} \ngiven_value: 0x{:016x}",
                a.ptr.as_ptr() as usize,
                b.ptr.as_ptr() as usize,
                &a as *const _ as usize
            );
            return Err(MemoryError::Allocation(format!(
                "Distance between parts below threshold: 0x{:016X}",
                actual_distance
            )));
        }

        info!("Mapped 2 fragments: at {:?} and {:?}", a.ptr, b.ptr);
        Ok((a, b))
    }

    /// Tries to allocate two objects of the same type with a default minimum distance in memory space of `0xFFFF`.
    pub fn alloc(strategy: FragStrategy) -> Result<(Frag<T>, Frag<T>), MemoryError> {
        Self::alloc2(strategy, 0xFFFF)
    }

    pub fn dealloc(ptr: Frag<T>) -> Result<(), MemoryError> {
        match ptr.strategy {
            FragStrategy::Direct => DirectAlloc::dealloc(ptr),
            FragStrategy::Map => MemoryMapAlloc::dealloc(ptr),
        }
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
/// let object = Frag::<usize>::alloc(FragStrategy::Map).unwrap();
/// ```
#[derive(Default, Clone)]
struct MemoryMapAlloc;

impl<T> Alloc<T> for MemoryMapAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc(config: Option<FragConfig>) -> Result<Frag<T>, Self::Error> {
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
                let c_ptr = libc::mmap(
                    &mut addr as *mut _ as *mut libc::c_void,
                    desired_alloc_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                    -1,
                    0,
                );

                info!("Preallocated segment addr: {:p}", c_ptr);

                if c_ptr == libc::MAP_FAILED {
                    warn!("Memory mapping failed");
                    continue;
                }

                if let Some(ref cfg) = config {
                    let actual_distance = (c_ptr as usize).abs_diff(cfg.last_address);
                    if actual_distance < cfg.min_distance {
                        warn!("New allocation distance to previous allocation is below threshold.");

                        dealloc_map(c_ptr, desired_alloc_size)?;
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

                let ptr = c_ptr as *mut T;

                if !ptr.is_null() {
                    let t = T::default();
                    ptr.write(t);

                    info!("Object succesfully written into mem location");

                    return Ok(Frag {
                        ptr: NonNull::new_unchecked(ptr),
                        strategy: FragStrategy::Map,
                        info: (c_ptr, desired_alloc_size),
                    });
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn dealloc(frag: Frag<T>) -> Result<(), Self::Error> {
        dealloc_map(frag.info.0, frag.info.1 as libc::size_t)
    }

    #[cfg(target_os = "windows")]
    fn alloc(_config: Option<FragConfig>) -> Result<Frag<T>, Self::Error> {
        // use random::thread_rng;
        // let mut rng = thread_rng();

        let handle = windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        loop {
            unsafe {
                // allocation prelude
                // {
                //     let r_addr = rng.gen::<u32>() >> 4;

                //     let random_mapping = windows::Win32::System::Memory::CreateFileMappingW(
                //         handle,
                //         std::ptr::null_mut(),
                //         windows::Win32::System::Memory::PAGE_READWRITE,
                //         0,
                //         r_addr,
                //         windows::core::PCWSTR(std::ptr::null_mut()),
                //     )
                //     .map_err(|e| MemoryError::Allocation(e.to_string()))?;

                //     if let Err(e) = last_error() {
                //         return Err(e);
                //     }

                //     let ptr = windows::Win32::System::Memory::MapViewOfFile(
                //         random_mapping,
                //         windows::Win32::System::Memory::FILE_MAP_ALL_ACCESS,
                //         0,
                //         0,
                //         r_addr as usize,
                //     );

                //     if let Err(e) = last_error() {
                //         return Err(e);
                //     }

                //     if let Some(ref cfg) = config {
                //         let actual_distance = (ptr as *const _ as usize).abs_diff(cfg.last_address);
                //         if actual_distance < cfg.min_distance {
                //             warn!(
                //                 "New allocation distance to previous allocation is below threshold: {}",
                //                 actual_distance
                //             );

                //             // remove previous file mapping
                //             if !windows::Win32::System::Memory::UnmapViewOfFile(ptr).as_bool() {
                //                 if let Err(e) = last_error() {
                //                     return Err(e);
                //                 }
                //             }

                //             continue;
                //         }
                //     }
                // }

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

                    let mem_view = windows::Win32::System::Memory::MapViewOfFile(
                        actual_mapping,
                        windows::Win32::System::Memory::FILE_MAP_ALL_ACCESS,
                        0,
                        0,
                        actual_size as usize,
                    );
                    let actual_mem = mem_view as *mut T;

                    if let Err(e) = last_error() {
                        return Err(e);
                    }

                    actual_mem.write(T::default());

                    return Ok(Frag {
                        ptr: NonNull::new_unchecked(actual_mem),
                        strategy: FragStrategy::Map,
                        info: Some((actual_mapping, mem_view)),
                    });
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn dealloc(frag: Frag<T>) -> Result<(), Self::Error> {
        if let Some((handle, view)) = frag.info {
            dealloc_map(handle, view)
        } else {
            Err(MemoryError::Allocation("Cannot release file handle".to_owned()))
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
/// let object = Frag::<usize>::alloc(FragStrategy::Direct).unwrap();
/// ```
#[derive(Default, Clone)]
struct DirectAlloc;

impl<T> Alloc<T> for DirectAlloc
where
    T: Default,
{
    type Error = MemoryError;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn alloc(config: Option<FragConfig>) -> Result<Frag<T>, Self::Error> {
        use random::{thread_rng, Rng};
        let mut rng = thread_rng();

        let actual_size = std::mem::size_of::<T>();

        let min = 0xFFFF;
        let max = 0xFFFF_FFFF;

        // pick a default, if system api call is not successful
        let default_page_size = 0x1000i64;

        let _pagesize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .unwrap_or(Some(default_page_size))
            .unwrap() as usize;

        // Within the loop we allocate a sufficiently "large" chunk of memory. A random
        // offset will be added to the returned pointer and the object will be written. This
        // actually leaks memory.
        loop {
            unsafe {
                let alloc_size = rng.gen::<usize>().min(min).max(max);
                let mem_ptr = {
                    // allocate some randomly sized chunk of memory
                    let c_ptr = libc::malloc(alloc_size);
                    if c_ptr.is_null() {
                        continue;
                    }

                    #[cfg(target_os = "macos")]
                    {
                        // on linux it isn't required to commit memory
                        let error = libc::madvise(c_ptr, actual_size, libc::MADV_WILLNEED);
                        if error != 0 {
                            error!("memory advise returned an error {}", error);
                            continue;
                        }
                    }

                    c_ptr
                };

                if let Some(ref cfg) = config {
                    let actual_distance = (mem_ptr as usize).abs_diff(cfg.last_address);
                    if actual_distance < cfg.min_distance {
                        warn!("New allocation distance to previous allocation is below threshold.");
                        dealloc_direct(mem_ptr)?;
                        continue;
                    }
                }

                // we are searching for some address in between
                let offset = rng.gen::<usize>().min(max - actual_size);
                let actual_mem = ((mem_ptr as usize) + offset) as *mut T;
                actual_mem.write(T::default());

                return Ok(Frag {
                    ptr: NonNull::new_unchecked(actual_mem),
                    strategy: FragStrategy::Direct,
                    info: (mem_ptr, alloc_size),
                });
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn dealloc(frag: Frag<T>) -> Result<(), Self::Error> {
        dealloc_direct(frag.info.0 as *mut libc::c_void)
    }

    #[cfg(target_os = "windows")]
    fn alloc(config: Option<FragConfig>) -> Result<Frag<T>, Self::Error> {
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
                        dealloc_direct(actual_mem)?;
                        continue;
                    }
                }

                let actual_mem = actual_mem as *mut T;
                actual_mem.write(T::default());
                return Ok(Frag {
                    ptr: NonNull::new_unchecked(actual_mem),
                    strategy: FragStrategy::Direct,
                    info: None,
                });
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn dealloc(frag: Frag<T>) -> Result<(), Self::Error> {
        dealloc_direct(NonNull::as_ptr(frag.ptr) as *mut libc::c_void)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn dealloc_map(ptr: *mut libc::c_void, size: libc::size_t) -> Result<(), MemoryError> {
    // munmap returns 0 on success
    unsafe {
        let res = libc::munmap(ptr, size);
        if res != 0 {
            let os_error = std::io::Error::last_os_error();
            return Err(MemoryError::Allocation(format!("Failed to munmap: {}", os_error)));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn dealloc_map(handle: windows::Win32::Foundation::HANDLE, view: *const libc::c_void) -> Result<(), MemoryError> {
    unsafe {
        // UnmapViewOfFile returns 0/FALSE when failing
        let res = windows::Win32::System::Memory::UnmapViewOfFile(view);
        if !res.as_bool() {
            if let Err(e) = last_error() {
                return Err(e);
            }
        }

        // CloseHandle returns 0/FALSE when failing
        let res = windows::Win32::Foundation::CloseHandle(handle);
        if !res.as_bool() {
            if let Err(e) = last_error() {
                return Err(e);
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn dealloc_direct(ptr: *mut libc::c_void) -> Result<(), MemoryError> {
    // double free cannot happen due to rust ownership typesystem
    unsafe {
        libc::free(ptr);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn dealloc_direct(ptr: *mut libc::c_void) -> Result<(), MemoryError> {
    use windows::Win32::System::Memory::VirtualFree;

    unsafe {
        // VirtualFree returns 0/FALSE if the function fails
        let res = VirtualFree(ptr, 0, windows::Win32::System::Memory::MEM_RELEASE).as_bool();
        if !res {
            if let Err(e) = last_error() {
                return Err(e);
            }
        }
    }
    Ok(())
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

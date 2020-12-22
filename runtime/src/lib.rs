// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![allow(clippy::many_single_char_names)]

use core::fmt;

#[macro_use]
#[cfg(target_os = "linux")]
extern crate memoffset;

#[macro_use]
#[cfg(unix)]
extern crate lazy_static;

#[cfg(unix)]
pub mod mem;

#[cfg(target_os = "linux")]
pub mod seccomp;

pub mod zone;

#[derive(PartialEq)]
pub enum Error {
    #[cfg(unix)]
    OsError {
        syscall: &'static str,
        errno: libc::c_int,
    },
    #[cfg(unix)]
    MemError(mem::Error),
    ZoneError(zone::Error),
    #[allow(dead_code)]
    Unreachable(&'static str),
}

impl Error {
    #[cfg(target_os = "linux")]
    pub fn os(syscall: &'static str) -> Self {
        Self::OsError {
            syscall,
            errno: unsafe { *libc::__errno_location() },
        }
    }

    #[cfg(target_os = "macos")]
    pub fn os(syscall: &'static str) -> Self {
        Self::OsError {
            syscall,
            errno: unsafe { *libc::__error() },
        }
    }

    #[allow(dead_code)]
    fn unreachable(msg: &'static str) -> Self {
        Self::Unreachable(msg)
    }
}

#[cfg(unix)]
impl From<mem::Error> for Error {
    fn from(e: mem::Error) -> Self {
        Error::MemError(e)
    }
}

#[cfg(unix)]
impl From<zone::Error> for Error {
    fn from(e: zone::Error) -> Self {
        Error::ZoneError(e)
    }
}

#[cfg(unix)]
fn strerror(errno: libc::c_int) -> &'static str {
    static mut BUF: [libc::c_char; 1024] = [0 as libc::c_char; 1024];
    unsafe {
        let res = libc::strerror_r(errno, BUF.as_mut_ptr(), BUF.len());
        assert_eq!(res, 0);

        let len = BUF.iter().position(|c| *c == 0).unwrap_or(BUF.len());
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(BUF.as_ptr() as *const u8, len))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(unix)]
            Self::OsError { syscall, errno } => f
                .debug_struct("OsError")
                .field("syscall", syscall)
                .field("errno", errno)
                .field("strerror", &strerror(*errno))
                .finish(),
            #[cfg(unix)]
            Self::MemError(me) => me.fmt(f),
            Self::ZoneError(ze) => ze.fmt(f),
            Self::Unreachable(msg) => f.write_fmt(format_args!("unreachable state: {}", msg)),
        }
    }
}

type Result<T, E = Error> = core::result::Result<T, E>;

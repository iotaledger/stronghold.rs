// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(dead_code)]
use core::fmt;

#[macro_use]
#[cfg(target_os = "linux")]
extern crate memoffset;

#[macro_use]
#[cfg(unix)]
extern crate lazy_static;

#[macro_use]
#[cfg(feature = "stdalloc")]
extern crate std;

pub mod mem;

pub mod secret;

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
    #[cfg(windows)]
    OsError {
        syscall: &'static str,
        errno: u32,
    },

    MemError(mem::Error),
    ZoneError(zone::Error),
    CryptoError(crypto::Error),
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

    #[cfg(target_os = "windows")]
    pub fn os(syscall: &'static str) -> Self {
        use winapi::um::errhandlingapi::GetLastError;

        Self::OsError {
            syscall,
            errno: { unsafe { GetLastError() } },
        }
    }

    #[allow(dead_code)]
    fn unreachable(msg: &'static str) -> Self {
        Self::Unreachable(msg)
    }
}

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

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::CryptoError(e)
    }
}

#[cfg(unix)]
fn strerror(errno: libc::c_int) -> &'static str {
    #[allow(clippy::unnecessary_cast)]
    static mut BUF: [libc::c_char; 1024] = [0 as libc::c_char; 1024];
    unsafe {
        let res = libc::strerror_r(errno, BUF.as_mut_ptr(), BUF.len());
        assert_eq!(res, 0);

        let len = BUF.iter().position(|c| *c == 0).unwrap_or(BUF.len());
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(BUF.as_ptr() as *const u8, len))
    }
}

#[cfg(windows)]
fn strerror(errno: u32) -> &'static str {
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::ntdef::WCHAR;
    use winapi::um::winbase::{FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};

    let lang_id = 0x0800 as DWORD;

    let mut buf = [0 as WCHAR; 2048];

    unsafe {
        let res = winapi::um::winbase::FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            core::ptr::null_mut(),
            errno as DWORD,
            lang_id,
            buf.as_mut_ptr(),
            buf.len() as DWORD,
            core::ptr::null_mut(),
        );

        assert_ne!(res, 0);

        let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());

        core::str::from_utf8_unchecked(core::slice::from_raw_parts(buf.as_ptr() as *const u8, len))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OsError { syscall, errno } => f
                .debug_struct("OsError")
                .field("syscall", syscall)
                .field("errno", errno)
                .field("strerror", &strerror(*errno))
                .finish(),
            Self::MemError(me) => me.fmt(f),
            Self::ZoneError(ze) => ze.fmt(f),
            Self::CryptoError(ce) => ce.fmt(f),
            Self::Unreachable(msg) => f.write_fmt(format_args!("unreachable state: {}", msg)),
        }
    }
}

type Result<T, E = Error> = core::result::Result<T, E>;

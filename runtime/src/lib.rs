// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![no_std]

use core::fmt;

#[macro_use]
extern crate memoffset;

#[macro_use]
extern crate lazy_static;

pub mod mem;
pub mod seccomp;
pub mod zone;

#[derive(PartialEq)]
pub enum Error {
    OsError { syscall: &'static str, errno: libc::c_int },
    MemError(mem::Error),
    ZoneError(zone::Error),
    Unreachable(&'static str),
}

impl Error {
    pub fn os(syscall: &'static str) -> Self {
        let errno = unsafe { *libc::__errno_location() };
        Self::OsError { syscall, errno }
    }

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
            Self::MemError(me) => me.fmt(f),
            Self::ZoneError(ze) => ze.fmt(f),
            Self::OsError { syscall, errno } => f
                .debug_struct("OsError")
                .field("syscall", syscall)
                .field("errno", errno)
                .field("strerror", &strerror(*errno))
                .finish(),
            Self::Unreachable(msg) => f.write_fmt(format_args!("unreachable state: {}", msg)),
        }
    }
}

type Result<T, E = Error> = core::result::Result<T, E>;

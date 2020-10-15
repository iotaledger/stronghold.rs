// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

#![no_std]

use core::fmt;

#[macro_use]
extern crate memoffset;

#[macro_use]
extern crate lazy_static;

pub mod mem;
pub mod zone;
pub mod seccomp;

#[derive(PartialEq)]
pub enum Error {
    OsError { syscall: &'static str, errno: libc::c_int },
    MemError(mem::Error),
    ZoneError(zone::Error),
}

impl Error {
    pub fn os(syscall: &'static str) -> Self {
        let errno = unsafe { *libc::__errno_location() };
        Self::OsError { syscall, errno }
    }
}

#[cfg(unix)]
fn strerror(errno: libc::c_int) -> &'static str {
    static mut BUF: [libc::c_char; 1024] = [0 as libc::c_char; 1024];
    unsafe {
        let res = libc::strerror_r(errno, BUF.as_mut_ptr(), BUF.len());
        assert_eq!(res, 0);

        let len = BUF.iter().position(|c| *c == 0).unwrap_or(BUF.len());
        core::str::from_utf8_unchecked(
            core::slice::from_raw_parts(BUF.as_ptr() as *const u8, len))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemError(me) => me.fmt(f),
            Self::ZoneError(ze) => ze.fmt(f),
            Self::OsError { syscall, errno } =>
                f.debug_struct("OsError")
                    .field("syscall", syscall)
                    .field("errno", errno)
                    .field("strerror", &strerror(*errno))
                    .finish()
        }
    }
}

type Result<T, E = Error> = core::result::Result<T, E>;

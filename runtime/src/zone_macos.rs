// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {
    UnexpectedExitCode { exit_code: libc::c_int },
    Signal { signo: libc::c_int },
    Timeout { runtime_ns: u64 },
    UnexpectedEOF,
    SuperfluousBytes,
}

impl Error {
    fn unexpected_exit_code(exit_code: libc::c_int) -> crate::Error {
        Self::UnexpectedExitCode { exit_code }.into()
    }

    fn signal(signo: libc::c_int) -> crate::Error {
        Self::Signal { signo }.into()
    }

    fn timeout(runtime: &libc::timespec) -> crate::Error {
        Self::Timeout { runtime_ns: runtime.tv_sec as u64 * 1_000_000_000 + runtime.tv_nsec as u64 }.into()
    }

    fn unexpected_eof() -> crate::Error {
        Self::UnexpectedEOF.into()
    }

    fn superfluous_bytes() -> crate::Error {
        Self::SuperfluousBytes.into()
    }
}

#[derive(Clone)]
pub struct ZoneSpec {
    guarded_allocator: bool,
}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {
            guarded_allocator: false,
        }
    }
}

impl ZoneSpec {
    pub fn secure_memory(&self) -> Self {
        let mut s = self.clone();
        s.guarded_allocator = true;
        s
    }

    pub fn random(&self) -> Self {
        self.clone()
    }
}

impl ZoneSpec {
    pub fn run<'b, F, T>(&self, f: F) -> crate::Result<<T as Transferable<'b>>::Out>
    where
        F: FnOnce() -> T,
        T: for<'a> Transferable<'a>,
    {
        fork(|| {
            if self.guarded_allocator {
                with_guarded_allocator(f)
            } else {
                f()
            }
        })
    }
}

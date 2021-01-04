// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {
    UnexpectedExitCode { exit_code: libc::c_int },
    Signal { signo: libc::c_int },
}

impl Error {
    fn unexpected_exit_code(exit_code: libc::c_int) -> crate::Error {
        Self::UnexpectedExitCode { exit_code }.into()
    }

    fn signal(signo: libc::c_int) -> crate::Error {
        Self::Signal { signo }.into()
    }
}

#[derive(Clone)]
struct ZoneSpec {
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
}

impl ZoneSpec {
    pub fn run<F, T>(&self, f: F) -> crate::Result<T>
    where
        F: FnOnce() -> T,
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

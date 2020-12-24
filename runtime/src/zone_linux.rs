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

pub struct ZoneSpec {
    seccomp: Option<crate::seccomp::Spec>,
}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {
            seccomp: Some(crate::seccomp::Spec::strict()),
        }
    }
}

impl ZoneSpec {
    pub fn run<F, T>(&self, f: F) -> crate::Result<T>
    where
        F: FnOnce() -> T,
    {
        fork(|| {
            if let Some(ref s) = self.seccomp {
                s.apply().unwrap();
            }

            f()
        })
    }
}

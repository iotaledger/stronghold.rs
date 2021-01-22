// Copyright 2020-2021 IOTA Stiftung
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
pub struct ZoneSpec {
    guarded_allocator: bool,
    seccomp: Option<crate::seccomp::Spec>,
}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {
            guarded_allocator: false,
            seccomp: Some(crate::seccomp::Spec::strict()),
        }
    }
}

impl ZoneSpec {
    pub fn secure_memory(&self) -> Self {
        let mut s = self.clone();
        s.guarded_allocator = true;
        s.seccomp = match self.seccomp {
            None => Some(crate::mem::seccomp_spec()),
            Some(ref s) => Some(s.join(crate::mem::seccomp_spec())),
        };
        s
    }
}

impl ZoneSpec {
    pub fn run<'b, F, T>(&self, f: F) -> crate::Result<Result<<T as Transferable<'b>>::Out, <T as Transferable<'b>>::Error>>
    where
        F: FnOnce() -> T,
        T: for<'a> Transferable<'a>,
    {
        fork(|| {
            if let Some(ref s) = self.seccomp {
                s.apply().unwrap();
            }

            if self.guarded_allocator {
                with_guarded_allocator(f)
            } else {
                f()
            }
        })
    }
}

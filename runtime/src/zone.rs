// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

#[derive(PartialEq, Debug)]
pub enum Error {
    UnexpectedExitCode { exit_code: libc::c_int },
    Signal { signo: libc::c_int },
    Unreachable(&'static str),
}

impl Error {
    fn unexpected_exit_code(exit_code: libc::c_int) -> crate::Error {
        crate::Error::ZoneError(Self::UnexpectedExitCode { exit_code })
    }

    fn signal(signo: libc::c_int) -> crate::Error {
        crate::Error::ZoneError(Self::Signal { signo })
    }

    fn unreachable(msg: &'static str) -> crate::Error {
        crate::Error::ZoneError(Self::Unreachable(msg))
    }
}

pub fn soft<F, T>(f: F) -> crate::Result<T>
where
    F: FnOnce() -> T,
{
    unsafe {
        let mut fds: [libc::c_int; 2] = [-1 as libc::c_int; 2];
        let r = libc::pipe(fds.as_mut_ptr());
        if r != 0 { return Err(crate::Error::os("pipe")) }

        let pid = libc::fork();
        if pid < 0 { return Err(crate::Error::os("fork")) }
        if pid == 0 {
            let r = libc::close(0);
            if r != 0 { libc::exit(1) }

            let r = libc::dup2(fds[1], 1); // NB dup to stdout in order to simplify seccomp filter
            if r < 0 { libc::exit(1) }

            let r = libc::close(2);
            if r != 0 { libc::exit(1) }

            let r = libc::close(fds[0]);
            if r != 0 { libc::exit(1) }

            // TODO: apply seccomp: provide a list of memory allocations, then:
            // 1. apply whitelist that includes the *exact* mprotect:s
            // 2. unlock the memory mappings
            // 3. further restrict the whitelist to disallow all mprotects

            let mut t = f();

            let _ = libc::write(1, &mut t as *mut _ as *mut libc::c_void, mem::size_of::<T>());
            // TODO: partial writes
            libc::exit(0)
        }

        let r = libc::close(fds[1]);
        if r != 0 { return Err(crate::Error::os("close")) }

        let mut st = 0;
        let r = libc::waitpid(pid, &mut st, 0);
        if r < 0 { return Err(crate::Error::os("waitpid")) }
        let ret = if libc::WIFEXITED(st) {
            let ec = libc::WEXITSTATUS(st);
            if ec == 0 {
                let mut t: mem::MaybeUninit<T> = mem::MaybeUninit::uninit();
                let _ = libc::read(fds[0], t.as_mut_ptr() as *mut libc::c_void, mem::size_of::<T>());
                // TODO: partial reads

                Ok(t.assume_init())
            } else {
                Err(Error::unexpected_exit_code(ec))
            }
        } else if libc::WIFSIGNALED(st) {
            Err(Error::signal(libc::WTERMSIG(st)))
        } else {
            Err(Error::unreachable("waitpid returned but: !WIFEXITED(st) && !WIFSIGNALED(st)"))
        };

        let r = libc::close(fds[0]);
        if r != 0 { return Err(crate::Error::os("close")) }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(soft(|| 7)?, 7);
        Ok(())
    }

    #[test]
    fn unexpected_exit_code() -> crate::Result<()> {
        assert_eq!(
            soft(|| unsafe { let _ = libc::exit(1); }),
            Err(Error::unexpected_exit_code(1))
        );
        Ok(())
    }

    #[test]
    fn signal() -> crate::Result<()> {
        assert_eq!(
            soft(|| unsafe {
                let _ = libc::kill(libc::getpid(), libc::SIGKILL);
            }),
            Err(Error::signal(libc::SIGKILL))
        );
        Ok(())
    }
}

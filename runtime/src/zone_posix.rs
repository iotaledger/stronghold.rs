// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

pub fn fork<F, T>(f: F) -> crate::Result<T>
where
    F: FnOnce() -> T,
{
    unsafe {
        #[allow(clippy::unnecessary_cast)]
        let mut fds: [libc::c_int; 2] = [-1 as libc::c_int; 2];
        let r = libc::pipe(fds.as_mut_ptr());
        if r != 0 {
            return Err(crate::Error::os("pipe"));
        }

        let pid = libc::fork();
        if pid < 0 {
            return Err(crate::Error::os("fork"));
        }
        if pid == 0 {
            let r = libc::close(0);
            if r != 0 {
                libc::_exit(1)
            }

            let r = libc::dup2(fds[1], 1); // NB dup to stdout in order to simplify seccomp filter
            if r < 0 {
                libc::_exit(1)
            }

            let r = libc::close(2);
            if r != 0 {
                libc::_exit(1)
            }

            let r = libc::close(fds[0]);
            if r != 0 {
                libc::_exit(1)
            }

            if cfg!(test) {
                extern crate std;
                std::panic::set_hook(std::boxed::Box::new(|_| libc::_exit(101)));
            }

            let mut t = f();

            let mut p = &mut t as *mut T as *mut u8;
            let mut n = mem::size_of::<T>();
            while n > 0 {
                let r = libc::write(1, p as *mut libc::c_void, n);
                if r < 0 {
                    libc::_exit(1)
                }
                n -= r as usize;
                p = p.add(r as usize);
            }

            libc::_exit(0)
        }

        let r = libc::close(fds[1]);
        if r != 0 {
            return Err(crate::Error::os("close"));
        }

        let mut st = 0;
        let r = libc::waitpid(pid, &mut st, 0);
        if r < 0 {
            return Err(crate::Error::os("waitpid"));
        }
        let ret = if libc::WIFEXITED(st) {
            let ec = libc::WEXITSTATUS(st);
            if ec == 0 {
                let mut t: mem::MaybeUninit<T> = mem::MaybeUninit::uninit();
                let mut n = mem::size_of::<T>();
                let mut p = t.as_mut_ptr() as *mut u8;
                while n > 0 {
                    let r = libc::read(fds[0], p as *mut libc::c_void, n);
                    if r < 0 {
                        return Err(crate::Error::os("read"));
                    }
                    n -= r as usize;
                    p = p.add(r as usize);
                }
                Ok(t.assume_init())
            } else {
                Err(Error::unexpected_exit_code(ec))
            }
        } else if libc::WIFSIGNALED(st) {
            Err(Error::signal(libc::WTERMSIG(st)))
        } else {
            Err(crate::Error::unreachable(
                "waitpid returned but: !WIFEXITED(st) && !WIFSIGNALED(st)",
            ))
        };

        let r = libc::close(fds[0]);
        if r != 0 {
            return Err(crate::Error::os("close"));
        }

        ret
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(fork(|| 7)?, 7);
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut bs = [0u8; 128];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, bs);
        Ok(())
    }

    #[test]
    #[ignore = "TODO: read and waitpid non-blocking"]
    fn pure_large_buffer() -> crate::Result<()> {
        let mut bs = [0u8; 1024 * 128];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, bs);
        Ok(())
    }

    #[test]
    #[allow(unnecessary_wraps)]
    fn unexpected_exit_code() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::exit(1);
            }),
            Err(Error::unexpected_exit_code(1))
        );
        Ok(())
    }

    #[test]
    #[allow(unnecessary_wraps)]
    fn signal() {
        assert_eq!(
            fork(|| unsafe {
                let _ = libc::kill(libc::getpid(), libc::SIGKILL);
            }),
            Err(Error::signal(libc::SIGKILL))
        );
        Ok(())
    }

    #[test]
    #[allow(unnecessary_wraps)]
    fn panic() -> crate::Result<()> {
        assert_eq!(fork(|| panic!("oopsie")), Err(Error::unexpected_exit_code(101)));
        Ok(())
    }
}

#[cfg(not(feature = "stdalloc"))]
fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
    f()
}

#[cfg(feature = "stdalloc")]
fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
    unsafe { crate::mem::stdalloc::guarded() };
    let a = f();
    unsafe { crate::mem::stdalloc::std() };
    a
}

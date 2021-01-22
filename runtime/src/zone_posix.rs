// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

pub fn fork<'b, F, T>(f: F) -> crate::Result<Result<<T as Transferable<'b>>::Out, <T as Transferable<'b>>::Error>>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
    unsafe {
        #[allow(clippy::unnecessary_cast)]
        let mut fds = [-1 as libc::c_int; 2];
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

            restore_test_panic_hook();

            let t = f();

            for b in t.transfer() {
                let mut bs = [*b];
                let r = libc::write(1, &mut bs as *mut _ as *mut libc::c_void, 1);
                if r < 0 {
                    libc::_exit(1)
                }
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
                receive::<T>(fds[0])
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
unsafe fn restore_test_panic_hook() {
    extern crate std;
    std::panic::set_hook(std::boxed::Box::new(|_| libc::_exit(101)));
}

#[cfg(not(test))]
unsafe fn restore_test_panic_hook() {
}

fn ensure_eof(fd: libc::c_int) -> crate::Result<()> {
    let mut bs = [0];
    let r = unsafe { libc::read(fd, &mut bs as *mut _ as *mut libc::c_void, 1) };
    if r < 0 {
        Err(crate::Error::os("read"))
    } else if r != 0 {
        Err(crate::Error::ZoneError(Error::SuperfluousBytes))
    } else {
        Ok(())
    }
}

const RECEIVE_BUFFER: usize = 256;

fn receive<'b, T>(fd: libc::c_int) -> crate::Result<Result<<T as Transferable<'b>>::Out, <T as Transferable<'b>>::Error>>
where
    T: for <'a> Transferable<'a>,
{
    let mut st = None;
    match T::receive(&mut st, core::iter::empty()) {
        TransferableState::Done(o) => {
            ensure_eof(fd)?;
            Ok(Ok(o))
        }
        TransferableState::Err(e) => Ok(Err(e)),
        TransferableState::Continue => {
            let mut ret = None;
            while ret.is_none() {
                let mut bs = [0; RECEIVE_BUFFER];
                let r = unsafe { libc::read(fd, &mut bs as *mut _ as *mut libc::c_void, bs.len()) };
                if r < 0 {
                    return Err(crate::Error::os("read"));
                }
                if r == 0 {
                    return Err(crate::Error::ZoneError(Error::UnexpectedEOF));
                }

                match T::receive(&mut st, bs[..(r as usize)].iter()) {
                    TransferableState::Done(o) => {
                        ensure_eof(fd)?;
                        ret = Some(Ok(o))
                    }
                    TransferableState::Err(e) => ret = Some(Err(e)),
                    TransferableState::Continue => (),
                }
            }
            Ok(ret.unwrap())
        }
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(fork(|| 7u8)?, Ok(7u8));
        assert_eq!(fork(|| 7u32)?, Ok(7u32));
        assert_eq!(fork(|| -7i32)?, Ok(-7i32));
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut bs = [0u8; RECEIVE_BUFFER/2];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        let mut bs = [0u8; RECEIVE_BUFFER];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        let mut bs = [0u8; RECEIVE_BUFFER*2];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        Ok(())
    }

    //#[test]
    //#[ignore = "TODO: read and waitpid non-blocking"]
    //fn pure_large_buffer() -> crate::Result<()> {
        //let mut bs = [0u8; 1024*128];
        //OsRng.fill_bytes(&mut bs);
        //assert_eq!(fork(|| bs)?, bs);
        //Ok(())
    //}

    #[test]
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
    #[allow(unreachable_code)]
    fn unexpected_eof() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::exit(0);
                7
            }),
            Err(crate::Error::ZoneError(Error::UnexpectedEOF))
        );
        Ok(())
    }

    #[test]
    #[allow(unreachable_code)]
    fn superfluous_bytes() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
            }),
            Err(crate::Error::ZoneError(Error::SuperfluousBytes))
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                9u8
            }),
            Ok(Err(Error::SuperfluousBytes))
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                [1, 2, 3, 4]
            }),
            Ok(Err(Error::SuperfluousBytes))
        );

        Ok(())
    }

    #[test]
    fn signal() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                let _ = libc::kill(libc::getpid(), libc::SIGKILL);
            }),
            Err(Error::signal(libc::SIGKILL))
        );
        Ok(())
    }

    #[test]
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

pub fn fork<'b, F, T>(f: F) -> crate::Result<<T as Transferable<'b>>::Out>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
    unsafe {
        let start = now()?;
        let (pid, fd) = spawn_child(f)?;
        wait_child::<T>(pid, fd, &start)
    }
}

unsafe fn now() -> crate::Result<libc::timespec> {
    let mut start = mem::MaybeUninit::uninit();
    let r = libc::clock_gettime(libc::CLOCK_MONOTONIC, start.as_mut_ptr());
    if r == 0 {
        Ok(start.assume_init())
    } else {
        Err(crate::Error::os("clock_gettime(CLOCK_MONOTONIC)"))
    }
}

fn between(a: &libc::timespec, b: &libc::timespec) -> libc::timespec {
    if a.tv_sec < b.tv_sec {
        libc::timespec {
            tv_sec: b.tv_sec - a.tv_sec,
            tv_nsec: (1_000_000_000 - a.tv_nsec) + b.tv_nsec,
        }
    } else if a.tv_sec > b.tv_sec {
        libc::timespec {
            tv_sec: a.tv_sec - b.tv_sec,
            tv_nsec: (1_000_000_000 - b.tv_nsec) + a.tv_nsec,
        }
    } else if a.tv_nsec < b.tv_nsec {
        libc::timespec {
            tv_sec: 0,
            tv_nsec: b.tv_nsec - a.tv_nsec,
        }
    } else {
        libc::timespec {
            tv_sec: 0,
            tv_nsec: a.tv_nsec - b.tv_nsec,
        }
    }
}

fn lt(a: &libc::timespec, b: &libc::timespec) -> bool {
    a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_nsec < b.tv_nsec)
}

unsafe fn spawn_child<'b, F, T>(f: F) -> crate::Result<(libc::pid_t, libc::c_int)>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
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
    if pid > 0 {
        let r = libc::close(fds[1]);
        if r != 0 {
            return Err(crate::Error::os("close"));
        }
        return Ok((pid, fds[0]));
    }

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

const SOFT_TIMEOUT_LIMIT: libc::timespec = libc::timespec {
    tv_sec: 3,
    tv_nsec: 0,
};
const SOFT_TIMEOUT_SIGNAL: libc::c_int = libc::SIGINT;

const HARD_TIMEOUT_LIMIT: libc::timespec = libc::timespec {
    tv_sec: 4,
    tv_nsec: 0,
};
const HARD_TIMEOUT_SIGNAL: libc::c_int = libc::SIGKILL;

unsafe fn wait_child<'b, T>(pid: libc::pid_t, fd: libc::c_int, start: &libc::timespec) -> crate::Result<<T as Transferable<'b>>::Out>
where
    T: for <'a> Transferable<'a>,
{
    set_non_blocking(fd)?;

    let mut wait = None;
    let mut hup = false;
    let mut st: Option<T::State> = None;
    let mut tst = T::receive(&mut st, &mut core::iter::empty(), false);

    loop {
        match wait {
            Some(Err(e)) => {
                let r = libc::close(fd);
                if r != 0 {
                    return Err(crate::Error::os("close"));
                }

                return Err(e);
            }
            Some(Ok(())) => if let Some(o) = tst {
                let r = libc::close(fd);
                if r != 0 {
                    return Err(crate::Error::os("close"));
                }

                return Ok(o);
            } else if hup {
                // NB I suspect this can yield false negatives in the scenario that the process is
                // succesfully waited for, the pipe is hung up but still has buffered data
                if let Some(o) = T::receive(&mut st, &mut core::iter::empty(), true) {
                    let r = libc::close(fd);
                    if r != 0 {
                        return Err(crate::Error::os("close"));
                    }

                    return Ok(o);
                }
            }
            None => wait = attempt_wait_child(pid)?,
        }

        let mut fds = [
            libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
        ];

        let r = libc::poll(fds.as_mut_ptr(), if hup { 0 } else { 1 }, 100);
        if r == -1 {
            return Err(crate::Error::os("poll"));
        }
        if r == 0 {
            let n = now()?;

            if !lt(&between(start, &n), &SOFT_TIMEOUT_LIMIT) {
                if wait.is_none() {
                    libc::kill(pid, SOFT_TIMEOUT_SIGNAL);
                }
            }

            let rt = between(start, &n);
            if !lt(&rt, &HARD_TIMEOUT_LIMIT) {
                let r = libc::close(fd);
                if r != 0 {
                    return Err(crate::Error::os("close"));
                }

                if wait.is_none() {
                    libc::kill(pid, HARD_TIMEOUT_SIGNAL);
                }

                return Err(Error::timeout(&rt));
            }
        }

        if (fds[0].revents & libc::POLLHUP) > 0 {
            hup = true;
            fds[0].revents &= !libc::POLLHUP;
        }

        if (fds[0].revents & libc::POLLIN) > 0 {
            tst = receive::<T>(&mut st, fds[0].fd)?;
            fds[0].revents &= !libc::POLLIN;
        }

        if fds[0].revents != 0 {
            todo!("unhandled events: {}", fds[0].revents)
        }
    }
}

unsafe fn attempt_wait_child(pid: libc::pid_t) -> crate::Result<Option<crate::Result<()>>> {
    let mut st = 0;
    let r = libc::waitpid(pid, &mut st, libc::WNOHANG);
    if r < 0 {
        Err(crate::Error::os("waitpid"))
    } else if r == 0 {
        Ok(None)
    } else {
        if libc::WIFEXITED(st) {
            let ec = libc::WEXITSTATUS(st);
            if ec == 0 {
                Ok(Some(Ok(())))
            } else {
                Ok(Some(Err(Error::unexpected_exit_code(ec))))
            }
        } else if libc::WIFSIGNALED(st) {
            Ok(Some(Err(Error::signal(libc::WTERMSIG(st)))))
        } else {
            Err(crate::Error::unreachable(
                    "waitpid returned but: !WIFEXITED(st) && !WIFSIGNALED(st)"))
        }
    }
}

unsafe fn set_non_blocking(fd: libc::c_int) -> crate::Result<()> {
    let f = libc::fcntl(fd, libc::F_GETFL);
    if f == -1 {
        return Err(crate::Error::os("fcntl(F_GETFL)"));
    }

    let r = libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK);
    if r != -1 {
        Ok(())
    } else {
        Err(crate::Error::os("fcntl(F_SETFL)"))
    }
}

const RECEIVE_BUFFER: usize = 256;

fn receive<'b, T>(st: &mut Option<<T as Transferable<'b>>::State>, fd: libc::c_int) -> crate::Result<Option<<T as Transferable<'b>>::Out>>
where
    T: for <'a> Transferable<'a>,
{
    let mut ret = None;
    while ret.is_none() {
        let mut bs = [0; RECEIVE_BUFFER];
        let r = unsafe { libc::read(fd, &mut bs as *mut _ as *mut libc::c_void, bs.len()) };
        let errno = unsafe { *libc::__errno_location() };
        if r < 0 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK ) {
            return Ok(None);
        }
        if r < 0 {
            return Err(crate::Error::os("read while receiving data"));
        }

        ret = T::receive(st, &mut bs[..(r as usize)].iter(), r == 0);
    }
    Ok(ret)
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(fork(|| 7u8)?, Ok(7u8));
        assert_eq!(fork(|| 7u32)?, Ok(7u32));
        assert_eq!(fork(|| -7i32)?, Ok(-7i32));
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut rng = StdRng::from_entropy();

        let mut bs = [0u8; RECEIVE_BUFFER/2];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        let mut bs = [0u8; RECEIVE_BUFFER];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        let mut bs = [0u8; RECEIVE_BUFFER*2];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, Ok(bs));

        Ok(())
    }

    #[test]
    #[cfg(feature = "stdalloc")]
    fn vec() -> crate::Result<()> {
        let bs = test_utils::fresh::bytestring();
        assert_eq!(fork(|| bs.as_slice())?, Ok(bs));

        Ok(())
    }

    #[test]
    fn unexpected_exit_code() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::_exit(1);
            }),
            Err(Error::unexpected_exit_code(1))
        );
        Ok(())
    }

    #[test]
    #[allow(unreachable_code)]
    fn unexpected_eof_when_nothing_is_written() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::_exit(0);
                7u32
            })?,
            Err(TransferError::UnexpectedEOF)
        );
        Ok(())
    }

    #[test]
    #[allow(unreachable_code)]
    fn unexpected_eof_some_bytes_written() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::write(1, [1u8, 2u8].as_ptr() as *const libc::c_void, 2);
                libc::_exit(0);
                7u32
            })?,
            Err(TransferError::UnexpectedEOF)
        );
        Ok(())
    }

    #[test]
    #[allow(unreachable_code)]
    #[ignore = "TODO: tuples (or any combination of transferables requires that the eof detection is done by the loop itself"]
    fn superfluous_bytes() -> crate::Result<()> {
        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
            })?,
            Err(TransferError::SuperfluousBytes)
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                9u8
            })?,
            Err(TransferError::SuperfluousBytes)
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                [1, 2, 3, 4]
            })?,
            Err(TransferError::SuperfluousBytes)
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
    #[ignore = "figure out how we can combine/override the test runners panic handler"]
    fn panic() -> crate::Result<()> {
        assert_eq!(fork(|| panic!("oopsie")), Err(Error::unexpected_exit_code(102)));
        Ok(())
    }

    #[test]
    fn soft_timeout() {
        assert_eq!(
            fork(|| unsafe { libc::sleep(SOFT_TIMEOUT_LIMIT.tv_sec as u32 * 2) }),
            Err(Error::signal(SOFT_TIMEOUT_SIGNAL))
        );
    }

    #[test]
    fn hard_timeout() -> crate::Result<()> {
        match fork(|| unsafe {
            let mut ss = mem::MaybeUninit::uninit();
            libc::sigemptyset(ss.as_mut_ptr());
            libc::sigaddset(ss.as_mut_ptr(), SOFT_TIMEOUT_SIGNAL);
            libc::sigprocmask(libc::SIG_BLOCK, ss.as_ptr(), core::ptr::null_mut());

            libc::sleep(HARD_TIMEOUT_LIMIT.tv_sec as u32 * 2)
        }) {
            Err(crate::Error::ZoneError(Error::Timeout { .. })) => Ok(()),
            r => panic!("unexpected return value: {:?}", r)
        }
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

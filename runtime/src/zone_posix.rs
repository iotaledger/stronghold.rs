// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

pub fn fork<'b, F, T>(f: F) -> crate::Result<<T as Transferable<'b>>::Out>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
    unsafe {
        let (pid, fd) = spawn_child(f)?;
        wait_child::<T>(pid, fd)
    }
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

unsafe fn wait_child<'b, T>(pid: libc::pid_t, fd: libc::c_int) -> crate::Result<<T as Transferable<'b>>::Out>
where
    T: for <'a> Transferable<'a>,
{
    let mut ss = mem::MaybeUninit::uninit();
    if libc::sigemptyset(ss.as_mut_ptr()) != 0 {
        return Err(crate::Error::os("sigemptyset"));
    }
    if libc::sigaddset(ss.as_mut_ptr(), libc::SIGCHLD) != 0 {
        return Err(crate::Error::os("sigaddset"));
    }

    let mut oss = mem::MaybeUninit::uninit();
    let r = libc::pthread_sigmask(libc::SIG_BLOCK, ss.as_ptr(), oss.as_mut_ptr());
    if r == -1 {
        return Err(crate::Error::os("pthread_sigmask(SIG_BLOCK)"));
    }

    let sfd = libc::signalfd(-1, ss.as_ptr(), libc::SFD_NONBLOCK);
    if sfd < 0 {
        return Err(crate::Error::os("signalfd"));
    }

    set_non_blocking(fd)?;

    let mut fds = [
        libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 },
    ];

    let mut wait = None;
    let mut st: Option<T::State> = None;
    let mut tst = T::receive(&mut st, core::iter::empty(), false);

    loop {
        match wait {
            Some(Err(_)) => break,
            Some(Ok(())) => if tst.is_some() {
                break
            }
            None => (),
        }

        let r = libc::poll(fds.as_mut_ptr(), fds.len() as u64, -1);
        if r == -1 {
            return Err(crate::Error::os("poll"));
        }
        if r == 0 {
            return Err(crate::Error::os("poll timed out unexpectedly"));
        }

        if (fds[0].revents & libc::POLLHUP) > 0 {
            // TODO: eof = true; ?
        }

        if (fds[0].revents & libc::POLLIN) > 0 {
            tst = receive::<T>(&mut st, fds[0].fd)?;
        }

        if (fds[1].revents & libc::POLLIN) > 0 {
            loop {
                let mut si: mem::MaybeUninit<libc::signalfd_siginfo> = mem::MaybeUninit::uninit();
                let r = libc::read(fds[1].fd, si.as_mut_ptr() as *mut libc::c_void, mem::size_of::<libc::signalfd_siginfo>());
                let errno = *libc::__errno_location();
                if r < 0 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK ) {
                    break;
                }
                if r < 0 {
                    return Err(crate::Error::os("read signalfd"));
                } else if r != mem::size_of::<libc::signalfd_siginfo>() as isize {
                    return Err(crate::Error::unreachable("incorrect amount of bytes read from a signalfd"));
                }
                let si = si.assume_init();

                if si.ssi_signo != libc::SIGCHLD as u32 {
                    todo!("unexpected signal");
                }

                if si.ssi_pid != pid as u32 {
                    //continue;
                    todo!("unexpected pid: {} != {}", si.ssi_pid, pid);
                }

                let mut st = 0;
                let r = libc::waitpid(pid, &mut st, libc::WNOHANG);
                if r == 0 {
                    todo!("unexpected hanging waitpid acll");
                }
                if r < 0 {
                    return Err(crate::Error::os("waitpid"));
                }
                if libc::WIFEXITED(st) {
                    let ec = libc::WEXITSTATUS(st);
                    if ec == 0 {
                        wait = Some(Ok(()));
                    } else {
                        wait = Some(Err(Error::unexpected_exit_code(ec)));
                    }
                } else if libc::WIFSIGNALED(st) {
                    wait = Some(Err(Error::signal(libc::WTERMSIG(st))));
                } else {
                    return Err(crate::Error::unreachable(
                        "waitpid returned but: !WIFEXITED(st) && !WIFSIGNALED(st)",
                    ));
                }
            }
        }
    }

    let r = libc::close(fd);
    if r != 0 {
        return Err(crate::Error::os("close"));
    }

    let r = libc::close(sfd);
    if r != 0 {
        return Err(crate::Error::os("close"));
    }

    let r = libc::pthread_sigmask(libc::SIG_SETMASK, oss.as_ptr(), core::ptr::null_mut());
    if r == -1 {
        return Err(crate::Error::os("pthread_sigmask(SIG_SETMASK)"));
    }

    match wait {
        Some(r) => r?,
        None => return Err(crate::Error::unreachable("wait == None")),
    }

    Ok(tst.unwrap())
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

#[cfg(test)]
unsafe fn restore_test_panic_hook() {
    extern crate std;
    std::panic::set_hook(std::boxed::Box::new(|_| libc::_exit(101)));
}

#[cfg(not(test))]
unsafe fn restore_test_panic_hook() {
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

        ret = T::receive(st, bs[..(r as usize)].iter(), r == 0);
    }
    Ok(ret)
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
                libc::_exit(1);
            }),
            Err(Error::unexpected_exit_code(1))
        );
        Ok(())
    }

    #[test]
    #[allow(unreachable_code)]
    #[ignore]
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
    #[ignore]
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

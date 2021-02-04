// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

pub struct TimeoutSpec {
    pub time: libc::timespec,
    pub signal: libc::c_int,
}

pub struct Timeout {
    pub soft: Option<TimeoutSpec>,
    pub hard: Option<TimeoutSpec>,
    pub granularity_ms: libc::c_int,
}

impl Default for Timeout {
    fn default() -> Self {
        Self {
            soft: None,
            hard: None,
            granularity_ms: 100,
        }
    }
}

fn ms_to_timespec(ms: u32) -> libc::timespec {
    libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: (ms % 1000) as libc::c_long * 1_000_000,
    }
}

impl Timeout {
    pub fn soft_ms(self, ms: u32) -> Self {
        self.soft_ms_signal(ms, libc::SIGINT)
    }

    pub fn soft_ms_signal(mut self, ms: u32, signal: libc::c_int) -> Self {
        self.soft = Some(
            TimeoutSpec {
                time: ms_to_timespec(ms),
                signal,
            }
        );

        self
    }

    pub fn hard_ms(self, ms: u32) -> Self {
        self.hard_ms_signal(ms, libc::SIGKILL)
    }

    pub fn hard_ms_signal(mut self, ms: u32, signal: libc::c_int) -> Self {
        self.hard = Some(
            TimeoutSpec {
                time: ms_to_timespec(ms),
                signal,
            }
        );

        self
    }
}

pub fn fork<'b, F, T>(f: F) -> crate::Result<<T as Transferable<'b>>::Out>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
    fork_with_timeout(f, Timeout::default())
}

pub fn fork_with_timeout<'b, F, T>(f: F, t: Timeout) -> crate::Result<<T as Transferable<'b>>::Out>
where
    F: FnOnce() -> T,
    T: for <'a> Transferable<'a>,
{
    unsafe {
        let start = now()?;
        let (pid, fd) = spawn_child(f)?;
        let out = wait_child::<T>(pid, fd, &start, t);

        let r = libc::close(fd);
        if r != 0 {
            return Err(crate::Error::os("close"));
        }

        out
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

unsafe fn wait_child<'b, T>(pid: libc::pid_t, fd: libc::c_int, start: &libc::timespec, t: Timeout) -> crate::Result<<T as Transferable<'b>>::Out>
where
    T: for <'a> Transferable<'a>,
{
    set_non_blocking(fd)?;

    let mut wait = None;
    let mut hup = false;
    let mut st: Option<T::State> = None;
    let mut tst = T::receive(&mut st, &mut core::iter::empty());

    loop {
        if wait.is_none() {
            wait = attempt_wait_child(pid)?;
        }

        match wait {
            Some(Err(e)) => return Err(e),
            Some(Ok(())) => match tst {
                Some(o) => {
                    expect_eof(fd)?;
                    return Ok(o);
                }
                None => if hup {
                    set_blocking(fd)?;
                    return match receive::<T>(&mut st, fd)? {
                        Some(o) => Ok(o),
                        None => Err(Error::unexpected_eof()),
                    };
                }
            }
            None => (),
        }

        let mut fds = [
            libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
        ];

        let r = if tst.is_none() {
            let r = libc::poll(fds.as_mut_ptr(), 1, t.granularity_ms);
            if r == -1 {
                return Err(crate::Error::os("poll"));
            }
            r
        } else {
            let ts = ms_to_timespec(t.granularity_ms as u32);
            let r = libc::nanosleep(&ts as *const _, core::ptr::null_mut());
            if r == -1 {
                return Err(crate::Error::os("nanosleep"));
            }
            0
        };

        if r == 0 {
            let n = now()?;

            if let Some(ref ts) = t.soft {
                if !lt(&between(start, &n), &ts.time) && wait.is_none() {
                    libc::kill(pid, ts.signal);
                }
            }

            if let Some(ref ts) = t.hard {
                let rt = between(start, &n);
                if !lt(&rt, &ts.time) {
                    if wait.is_none() {
                        libc::kill(pid, ts.signal);
                    }

                    return Err(Error::timeout(&rt));
                }
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
    } else if libc::WIFEXITED(st) {
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

unsafe fn set_blocking(fd: libc::c_int) -> crate::Result<()> {
    let f = libc::fcntl(fd, libc::F_GETFL);
    if f == -1 {
        return Err(crate::Error::os("fcntl(F_GETFL)"));
    }

    let r = libc::fcntl(fd, libc::F_SETFL, f & !libc::O_NONBLOCK);
    if r != -1 {
        Ok(())
    } else {
        Err(crate::Error::os("fcntl(F_SETFL)"))
    }
}

const RECEIVE_BUFFER: usize = 256;

#[cfg(target_os = "linux")]
unsafe fn errno() -> libc::c_int {
    *libc::__errno_location()
}

#[cfg(target_os = "macos")]
unsafe fn errno() -> libc::c_int {
    *libc::__error()
}

unsafe fn receive<'b, T>(st: &mut Option<<T as Transferable<'b>>::State>, fd: libc::c_int) -> crate::Result<Option<<T as Transferable<'b>>::Out>>
where
    T: for <'a> Transferable<'a>,
{
    let mut ret = None;
    while ret.is_none() {
        let mut bs = [0; RECEIVE_BUFFER];
        let r = libc::read(fd, &mut bs as *mut _ as *mut libc::c_void, bs.len());
        let e = errno();
        if r == 0 || r < 0 && (e == libc::EAGAIN || e == libc::EWOULDBLOCK) {
            break
        }
        if r < 0 {
            return Err(crate::Error::os("read while receiving data"));
        }

        let mut i = bs[..(r as usize)].iter();
        ret = T::receive(st, &mut i);

        if i.next().is_some() {
            return Err(Error::superfluous_bytes());
        }
    }
    Ok(ret)
}

unsafe fn expect_eof(fd: libc::c_int) -> crate::Result<()>
{
    set_blocking(fd)?;

    let mut bs = [0; 1];
    let r = libc::read(fd, &mut bs as *mut _ as *mut libc::c_void, bs.len());
    match r {
        r if r < 0 => Err(crate::Error::os("read while expecting EOF")),
        r if r > 0 => Err(Error::superfluous_bytes()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(fork(|| 7u8)?, 7u8);
        assert_eq!(fork(|| 7u32)?, 7u32);
        assert_eq!(fork(|| -7i32)?, -7i32);
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut rng = StdRng::from_entropy();

        let mut bs = [0u8; RECEIVE_BUFFER/2];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, bs);

        let mut bs = [0u8; RECEIVE_BUFFER];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, bs);

        let mut bs = [0u8; RECEIVE_BUFFER*2];
        rng.fill_bytes(&mut bs);
        assert_eq!(fork(|| bs)?, bs);

        Ok(())
    }

    #[test]
    #[cfg(feature = "stdalloc")]
    fn vec() -> crate::Result<()> {
        let bs = test_utils::fresh::bytestring();
        assert_eq!(fork(|| bs.as_slice())?, bs);

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
            }),
            Err(Error::unexpected_eof())
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
            }),
            Err(Error::unexpected_eof())
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
            Err(Error::superfluous_bytes())
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                9u8
            }),
            Err(Error::superfluous_bytes())
        );

        assert_eq!(
            fork(|| unsafe {
                libc::write(1, &[7u8] as *const _ as *const libc::c_void, 1);
                [1, 2, 3, 4]
            }),
            Err(Error::superfluous_bytes())
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
        assert_eq!(fork(|| panic!("oopsie")), Err(Error::unexpected_exit_code(101)));
        Ok(())
    }

    #[test]
    fn soft_timeout_while_waiting_for_data() {
        let s = 1;
        let sig = libc::SIGINT;
        let t = Timeout::default().soft_ms_signal(s * 1000, sig);
        assert_eq!(
            fork_with_timeout(|| unsafe { libc::sleep(2 * s); 7 }, t),
            Err(Error::signal(sig))
        );
    }

    #[test]
    #[allow(unreachable_code)]
    fn soft_timeout_while_wait_for_process() {
        let s = 1;
        let sig = libc::SIGINT;
        let t = Timeout::default().soft_ms_signal(s * 1000, sig);
        assert_eq!(
            fork_with_timeout(|| unsafe {
                libc::write(1, &[8u8] as *const _ as *const libc::c_void, 1);
                libc::sleep(2 * s);
                libc::_exit(0);
                7u8
            }, t),
            Err(Error::signal(sig))
        );
    }

    #[test]
    fn hard_timeout_while_waiting_for_data() -> crate::Result<()> {
        let s = 1;
        let sig = libc::SIGKILL;
        let t = Timeout::default().hard_ms_signal(s * 1000, sig);
        match fork_with_timeout(|| unsafe {
            libc::sleep(2 * s); 7
        }, t) {
            Err(crate::Error::ZoneError(Error::Timeout { .. })) => Ok(()),
            r => panic!("unexpected return value: {:?}", r)
        }
    }

    #[test]
    #[allow(unreachable_code)]
    fn hard_timeout_while_waiting_for_process() -> crate::Result<()> {
        let s = 1;
        let sig = libc::SIGKILL;
        let t = Timeout::default().hard_ms_signal(s * 1000, sig);
        match fork_with_timeout(|| unsafe {
            libc::write(1, &[8u8] as *const _ as *const libc::c_void, 1);
            libc::sleep(2 * s);
            libc::_exit(0);
            7u8
        }, t) {
            Err(crate::Error::ZoneError(Error::Timeout { .. })) => Ok(()),
            r => panic!("unexpected return value: {:?}", r)
        }
    }

    #[test]
    fn soft_then_hard_timeout() -> crate::Result<()> {
        let s = 1;
        let soft_sig = libc::SIGINT;
        let hard_sig = libc::SIGKILL;
        let t = Timeout::default().soft_ms_signal(s * 1000, soft_sig).hard_ms_signal(2 * s * 1000, hard_sig);
        match fork_with_timeout(|| unsafe {
            let mut ss = mem::MaybeUninit::uninit();
            libc::sigemptyset(ss.as_mut_ptr());
            libc::sigaddset(ss.as_mut_ptr(), soft_sig);
            libc::sigprocmask(libc::SIG_BLOCK, ss.as_ptr(), core::ptr::null_mut());

            libc::sleep(3 * s)
        }, t) {
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

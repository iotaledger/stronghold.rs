// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem;

#[allow(dead_code)]
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/seccomp_bindings.rs"));
}

const PROGRAM_MAX_LENGTH: usize = 1024;

struct Program {
    len: usize,
    ops: [bindings::sock_filter; PROGRAM_MAX_LENGTH],
}

impl AsRef<Program> for Program {
    fn as_ref(&self) -> &Self {
        &self
    }
}

impl Program {
    fn empty() -> Self {
        Self {
            len: 0,
            ops: unsafe { mem::zeroed() },
        }
    }

    fn op(&mut self, code: bindings::__u32, k: bindings::__u32) {
        self.ops[self.len] = bindings::sock_filter {
            code: code as bindings::__u16,
            jt: 0,
            jf: 0,
            k,
        };
        self.len += 1;
    }

    fn jmp(&mut self, code: bindings::__u32, jt: bindings::__u8, jf: bindings::__u8, k: bindings::__u32) {
        self.ops[self.len] = bindings::sock_filter {
            code: (bindings::BPF_JMP | code) as bindings::__u16,
            jt,
            jf,
            k,
        };
        self.len += 1;
    }

    pub fn apply(&self) -> crate::Result<()> {
        let p = bindings::sock_fprog {
            len: self.len as libc::c_ushort,
            filter: self.ops.as_ptr() as *mut bindings::sock_filter,
        };

        let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if r != 0 {
            return Err(crate::Error::os("prctl(PR_SET_NO_NEW_PRIVS)"));
        }

        let r = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &p as *const _ as *const libc::c_void,
            )
        };
        if r != 0 {
            return Err(crate::Error::os("prctl(PR_SET_SECCOMP)"));
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct Spec {
    pub write_stdout: bool,
    pub write_stderr: bool,
    pub anonymous_mmap: bool,
    pub munmap: bool,
}

impl Spec {
    pub fn strict() -> Self {
        Self {
            write_stdout: true,
            write_stderr: false,
            anonymous_mmap: false,
            munmap: false,
        }
    }

    fn program(&self) -> Program {
        let mut p = Program::empty();

        p.op(
            bindings::BPF_LD | bindings::BPF_W | bindings::BPF_ABS,
            offset_of!(bindings::seccomp_data, nr) as bindings::__u32,
        );

        if self.anonymous_mmap {
            p.jmp(
                bindings::BPF_JEQ | bindings::BPF_K,
                0,
                1,
                libc::SYS_mmap as bindings::__u32,
            );
            p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);

            // TODO: restrict arguments (and exclude PROT_EXEC)
        }

        if self.munmap {
            p.jmp(
                bindings::BPF_JEQ | bindings::BPF_K,
                0,
                1,
                libc::SYS_munmap as bindings::__u32,
            );
            p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);
        }

        if self.write_stdout || self.write_stderr {
            if self.write_stderr && self.write_stdout {
                p.jmp(
                    bindings::BPF_JEQ | bindings::BPF_K,
                    0,
                    5,
                    libc::SYS_write as bindings::__u32,
                );
                p.op(
                    bindings::BPF_LD | bindings::BPF_W | bindings::BPF_ABS,
                    offset_of!(bindings::seccomp_data, args) as bindings::__u32,
                );
                p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 1, 1, 1);
                p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 0, 1, 2);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);
            } else if self.write_stdout {
                p.jmp(
                    bindings::BPF_JEQ | bindings::BPF_K,
                    0,
                    4,
                    libc::SYS_write as bindings::__u32,
                );
                p.op(
                    bindings::BPF_LD | bindings::BPF_W | bindings::BPF_ABS,
                    offset_of!(bindings::seccomp_data, args) as bindings::__u32,
                );
                p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 0, 1, 1);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);
            } else if self.write_stderr {
                p.jmp(
                    bindings::BPF_JEQ | bindings::BPF_K,
                    0,
                    4,
                    libc::SYS_write as bindings::__u32,
                );
                p.op(
                    bindings::BPF_LD | bindings::BPF_W | bindings::BPF_ABS,
                    offset_of!(bindings::seccomp_data, args) as bindings::__u32,
                );
                p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 0, 1, 2);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);
                p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);
            }
        }

        p.jmp(
            bindings::BPF_JEQ | bindings::BPF_K,
            0,
            1,
            libc::SYS_exit_group as bindings::__u32,
        );
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);

        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);

        p
    }

    pub fn apply(&self) -> crate::Result<()> {
        self.program().apply()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Debug;

    fn harness<T: PartialEq + Debug, F: FnOnce() -> T>(f: F) -> crate::Result<T> {
        crate::zone::soft(f)
    }

    fn expect_sigsys<T: PartialEq + Debug, F: FnOnce() -> T>(f: F) -> () {
        assert_eq!(
            harness(f),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal {
                signo: libc::SIGSYS
            }))
        );
    }

    #[test]
    fn deny_everything() {
        let mut p = Program::empty();
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);
        expect_sigsys(|| p.apply().unwrap());
    }

    #[test]
    fn strict() {
        assert_eq!(
            harness(|| {
                Spec::strict().apply().unwrap();
                7
            }),
            Ok(7)
        );
    }

    #[test]
    fn default() {
        assert_eq!(
            harness(|| {
                Spec::default().apply().unwrap();
                unsafe {
                    libc::_exit(0);
                }
            }),
            Ok(())
        );
    }

    #[test]
    fn default_rejects_write_stdout() {
        expect_sigsys(|| {
            Spec::default().apply().unwrap();
            unsafe { libc::write(1, "hello".as_ptr() as *const libc::c_void, 5) };
        });
    }

    #[test]
    fn stdout_but_rejects_write_stderr() {
        let s = Spec {
            write_stdout: true,
            ..Spec::default()
        };

        assert_eq!(
            harness(|| {
                s.apply().unwrap();
                "hello"
            }),
            Ok("hello")
        );

        expect_sigsys(|| {
            s.apply().unwrap();
            unsafe { libc::write(2, "hello".as_ptr() as *const libc::c_void, 5) };
        });
    }

    #[test]
    fn stderr_but_reject_write_stdout() {
        let s = Spec {
            write_stderr: true,
            ..Spec::default()
        };

        expect_sigsys(|| {
            s.apply().unwrap();
            "hello"
        });

        assert_eq!(
            harness(|| {
                s.apply().unwrap();
                unsafe { libc::write(2, "hello".as_ptr() as *const libc::c_void, 5) };
                unsafe { libc::_exit(0) };
            }),
            Ok(())
        );
    }
}

// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use core::mem;
use core::fmt::Debug;

#[allow(dead_code)]
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/seccomp_bindings.rs"));
}

const PROGRAM_MAX_LENGTH: usize = 1024;

pub struct Program {
    len: usize,
    ops: [bindings::sock_filter; PROGRAM_MAX_LENGTH],
}

impl AsRef<Program> for Program {
    fn as_ref(&self) -> &Self { &self }
}

impl Program {
    fn empty() -> Self {
        Self {
            len: 0,
            ops: unsafe { mem::zeroed() },
        }
    }

    pub fn deny_everything() -> Self {
        let mut p = Self::empty();
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);
        p
    }

    pub fn strict() -> Self {
        let mut p = Self::empty();

        p.op(bindings::BPF_LD | bindings::BPF_W | bindings::BPF_ABS,
            offset_of!(bindings::seccomp_data, nr) as bindings::__u32);

        p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 0, 1,
            libc::SYS_write as bindings::__u32);
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);

        p.jmp(bindings::BPF_JEQ | bindings::BPF_K, 0, 1,
            libc::SYS_exit_group as bindings::__u32);
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_ALLOW);
        p.op(bindings::BPF_RET | bindings::BPF_K, bindings::SECCOMP_RET_KILL_PROCESS);

        p
    }

    fn op(&mut self, code: bindings::__u32, k: bindings::__u32) {
        self.ops[self.len] = bindings::sock_filter {
            code: code as bindings::__u16, jt: 0, jf: 0, k };
        self.len += 1;
    }

    fn jmp(&mut self, code: bindings::__u32,
        jt: bindings::__u8, jf: bindings::__u8,
        k: bindings::__u32) {
        self.ops[self.len] = bindings::sock_filter {
            code: (bindings::BPF_JMP | code) as bindings::__u16, jt, jf, k };
        self.len += 1;
    }

    pub fn apply(&self) -> crate::Result<()> {
        let p = bindings::sock_fprog {
            len: self.len as libc::c_ushort,
            filter: self.ops.as_ptr() as *mut bindings::sock_filter,
        };

        let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if r != 0 { return Err(crate::Error::os("prctl(PR_SET_NO_NEW_PRIVS)")) }

        let r = unsafe {
            libc::prctl(libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &p as *const _ as *const libc::c_void)
        };
        if r != 0 { return Err(crate::Error::os("prctl(PR_SET_SECCOMP)")) }

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness<T: PartialEq + Debug, F: FnOnce() -> T>(f: F) -> crate::Result<T> {
        crate::zone::soft(f)
    }

    fn expect_sigsys<T: PartialEq + Debug, F: FnOnce() -> T>(f: F) -> () {
        assert_eq!(
            harness(f),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal { signo: libc::SIGSYS }))
        );
    }

    #[test]
    fn deny_everything() {
        expect_sigsys(|| Program::deny_everything().apply().unwrap());
    }

    #[test]
    fn strict() {
        assert_eq!(harness(|| { Program::strict().apply().unwrap(); 7 }), Ok(7));
    }
}

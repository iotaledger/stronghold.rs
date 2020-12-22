// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {
}

struct ZoneSpec {
}

impl ZoneSpec {
    pub fn run<F, T>(&self, f: F) -> crate::Result<T>
    where
        F: FnOnce() -> T,
    {
        Ok(f())
    }
}

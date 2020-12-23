// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {}

struct ZoneSpec {}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {}
    }
}

#[allow(dead_code)]
impl ZoneSpec {
    pub fn run<F, T>(&self, f: F) -> crate::Result<T>
    where
        F: FnOnce() -> T,
    {
        Ok(f())
    }
}

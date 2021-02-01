// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {}

#[derive(Clone)]
struct ZoneSpec {}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {}
    }
}

impl ZoneSpec {
    pub fn secure_memory(&self) -> Self {
        self.clone()
    }

    pub fn random(&self) -> Self {
        self.clone()
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

/// TODO: STUB FUNCTION
#[allow(clippy::extra_unused_lifetimes)]
pub fn fork<'b, F, T>(f: F) -> crate::Result<T>
where
    F: FnOnce() -> T,
{
    let res = f();

    Ok(res)
}

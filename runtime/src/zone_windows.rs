// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(PartialEq, Debug)]
pub enum Error {
}

pub fn soft<F, T>(f: F) -> crate::Result<T>
where
    F: FnOnce() -> T,
{
    Ok(f())
}

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[macro_export]
macro_rules! error_line {
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

pub mod provider;
pub mod test_vault;

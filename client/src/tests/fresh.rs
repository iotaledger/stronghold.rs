// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::keys::slip10::Chain;
use std::fmt::Write;
pub use stronghold_utils::{random::*, test_utils};

use crate::Location;

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(variable_bytestring(4096), variable_bytestring(4096))
}

/// Creates a random hd_path.
pub fn hd_path() -> (String, Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = random::<u32>() & 0x7fffff;
        write!(&mut s, "/{}'", i).expect("Failed to write path into string");
        is.push(i);
    }
    (s, Chain::from_u32_hardened(is))
}

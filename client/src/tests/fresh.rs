// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::keys::slip10::Chain;
pub use stronghold_utils::{random::*, test_utils};

use crate::Location;

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(bytestring(4096), bytestring(4096))
}

/// Creates a random hd_path.
pub fn hd_path() -> (String, Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i));
        is.push(i);
    }
    (s, Chain::from_u32_hardened(is))
}

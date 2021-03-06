// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{keys::slip10::Chain, utils::rand::fill};
pub use stronghold_utils::test_utils::{self, fresh::*};

use crate::{Location, RecordHint};

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    fill(&mut bs).expect("Unable to fill record hint");
    bs.into()
}

pub fn location() -> Location {
    Location::generic(bytestring(), bytestring())
}

pub fn passphrase() -> Option<String> {
    if coinflip() {
        Some(string())
    } else {
        None
    }
}

pub fn hd_path() -> (String, Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i.to_string()));
        is.push(i);
    }
    (s, Chain::from_u32_hardened(is))
}

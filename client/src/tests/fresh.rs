// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    keys::{bip39, slip10},
    utils::rand,
};
pub use stronghold_utils::test_utils::{self, fresh::*};

use crate::{Location, RecordHint, SLIP10Chain};

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    rand::fill(&mut bs).expect("Unable to fill record hint");
    bs.into()
}

pub fn location() -> Location {
    Location::generic(bytestring(), bytestring())
}

pub fn passphrase() -> bip39::Passphrase {
    if coinflip() {
        bip39::Passphrase::from(string())
    } else {
        bip39::Passphrase::new()
    }
}

pub fn slip10_hd_path() -> (String, SLIP10Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = ::rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i.to_string()));
        is.push(i);
    }
    (s, is.into_iter().map(slip10::Segment::harden).map(Into::into).collect())
}

pub fn slip10_path() -> (String, SLIP10Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = ::rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i.to_string()));
        is.push(i);
    }
    (s, is)
}

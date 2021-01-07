// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use test_utils::fresh::*;

use iota_stronghold::{RecordHint, Location, hd};

use rand::Rng;

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
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

pub fn hd_path() -> (String, hd::Chain) {
    ("m".to_string(), hd::Chain::empty())
}

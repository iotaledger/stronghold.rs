// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;
use std::iter::repeat;

use vault::RecordHint;

pub fn data() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let l = rng.gen_range(0, 3) * rng.gen_range(1, 28);
    let mut bs: Vec<u8> = repeat(0u8).take(l).collect();
    rng.fill(&mut bs[..]);
    bs
}

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
    bs.into()
}

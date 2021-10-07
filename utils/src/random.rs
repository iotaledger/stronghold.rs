// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::distributions::{Distribution, Standard};

// Random value for `T`.
pub fn random<T>() -> T
where
    Standard: Distribution<T>,
{
    rand::random()
}

// Random Bytestring with random length in range 1..4096.
pub fn bytestring() -> Vec<u8> {
    let s = (random::<usize>() % 4095) + 1;
    let mut bs = Vec::with_capacity(s);
    for _ in 1..s {
        bs.push(random());
    }
    bs
}

// Random string with random length in range 1..4096.
pub fn string() -> String {
    let l = (random::<usize>() % 4095) + 1;

    let mut s = String::with_capacity(l);
    for _ in 0..l {
        s.push(random())
    }
    s
}

// Random bool.
pub fn coinflip() -> bool {
    random()
}

// Random usize in range 0..upper_bound (excluding the upper bound).
pub fn usize(upper_bound: usize) -> usize {
    random::<usize>() % upper_bound
}

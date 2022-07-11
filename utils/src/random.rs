// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::{
    distributions::{Alphanumeric, Distribution, Standard},
    Rng,
};

// Random value for `T`.
pub fn random<T>() -> T
where
    Standard: Distribution<T>,
{
    rand::random()
}

// Random Bytestring with random length in range 1..max_len.
pub fn variable_bytestring(max_len: usize) -> Vec<u8> {
    let s = (random::<usize>() % (max_len - 1)) + 1;
    let mut bs = Vec::with_capacity(s);
    for _ in 0..s {
        bs.push(random());
    }
    bs
}

/// Returns a fixed sized byte string
pub fn fixed_bytestring(len: usize) -> Vec<u8> {
    let mut rmut = rand::thread_rng();
    std::iter::repeat_with(|| rmut.gen()).take(len).collect()
}

// Random string with random length in range 1..max_len.
pub fn string(max_len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(rand::thread_rng().gen_range(1..max_len))
        .map(char::from)
        .collect()
}

// Random bool.
pub fn coinflip() -> bool {
    random()
}

// Random usize in range 0..upper_bound (excluding the upper bound).
pub fn usize(upper_bound: usize) -> usize {
    random::<usize>() % upper_bound
}

/// Returns a random passphrase as String
pub fn passphrase() -> Option<String> {
    Some(string(1024))
}

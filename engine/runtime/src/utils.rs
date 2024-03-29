// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use random::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

pub fn xor(payload: &[u8], noise: &[u8], size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for i in 0..size {
        data[i] = noise[i] ^ payload[i];
    }
    data
}

pub fn random_vec(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut v = vec![0u8; size];
    rng.fill_bytes(&mut v);

    v
}

// Creates random file name and join it to the storing directory
pub fn random_fname(size: usize) -> String {
    let fname: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect();
    fname
}

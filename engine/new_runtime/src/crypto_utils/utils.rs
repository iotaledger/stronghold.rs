// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub fn xor(payload: &[u8], noise: &[u8], size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for i in 0..size {
        data[i] = noise[i] ^ payload[i];
    }
    data
}

// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub fn bytestring() -> Vec<u8> {
    let s = if rand::random::<u8>() % 4 == 0 {
        0
    } else {
        rand::random::<usize>() % 4096
    };

    let mut bs = Vec::with_capacity(s);
    for _ in 1..s {
        bs.push(rand::random());
    }
    bs
}

pub fn non_empty_bytestring() -> Vec<u8> {
    let s = (rand::random::<usize>() % 4096) + 1;
    let mut bs = Vec::with_capacity(s);
    for _ in 1..s {
        bs.push(rand::random());
    }
    bs
}

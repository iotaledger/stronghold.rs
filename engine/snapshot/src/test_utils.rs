// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::io::{Seek, SeekFrom, Read, Write};
use std::fs::File;

pub mod fresh {
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
}

pub fn corrupt(bs: &mut [u8]) {
    if bs.is_empty() {
        return;
    }
    loop {
        let i = rand::random::<usize>() % bs.len();
        let b = bs[i];
        bs[i] = rand::random();
        if b != bs[i] && rand::random() {
            break;
        }
    }
}

pub fn seek_to_beginning(f: &mut File) {
    f.seek(SeekFrom::Start(0)).unwrap();
}

pub fn corrupt_file(f: &mut File) {
    seek_to_beginning(f);
    let mut bs = Vec::new();
    f.read_to_end(&mut bs).unwrap();

    corrupt(&mut bs);

    seek_to_beginning(f);
    f.write(&bs).unwrap();

    seek_to_beginning(f);
}

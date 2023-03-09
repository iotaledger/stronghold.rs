// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::random;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::Path,
};

pub fn corrupt(bs: &mut [u8]) {
    if bs.is_empty() {
        return;
    }
    loop {
        let i = random::usize(bs.len());
        let b = bs[i];
        bs[i] = random::random();
        if b != bs[i] && random::coinflip() {
            break;
        }
    }
}

fn seek_to_beginning(f: &mut File) {
    f.rewind().unwrap();
}

pub fn corrupt_file(f: &mut File) {
    seek_to_beginning(f);
    let mut bs = Vec::new();
    f.read_to_end(&mut bs).unwrap();

    corrupt(&mut bs);

    seek_to_beginning(f);
    f.write_all(&bs).unwrap();

    seek_to_beginning(f);
}

pub fn corrupt_file_at(p: &Path) {
    let mut f: File = OpenOptions::new().write(true).read(true).open(p).unwrap();
    corrupt_file(&mut f)
}

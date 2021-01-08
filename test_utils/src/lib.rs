// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub mod fresh;

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

fn seek_to_beginning(f: &mut File) {
    f.seek(SeekFrom::Start(0)).unwrap();
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

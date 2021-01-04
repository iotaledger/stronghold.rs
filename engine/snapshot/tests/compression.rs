// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str;

use snapshot::{compress, decompress};

const LOREM_STR: &str = include_str!("lorem.txt");
const ZAPPA_STR: &str = include_str!("zappa.txt");

fn invert(s: &str) {
    let compressed = compress(s.as_bytes());
    // println!("Compressed {} into {:?}", s, compressed);
    let decompressed = decompress(&compressed).unwrap();
    // println!("Decompressed into {:?}", str::from_utf8(&decompressed).unwrap());
    assert_eq!(decompressed, s.as_bytes());
    println!(
        "original size: {}, compressed size: {}",
        decompressed.len(),
        compressed.len()
    );
    assert_eq!(decompressed.len(), s.as_bytes().len());
}

#[test]
fn test_compression_lorem_ipsum() {
    invert(LOREM_STR);
}

#[test]
fn test_compression_zappa() {
    invert(ZAPPA_STR);
}

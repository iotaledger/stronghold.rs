// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str;

use proptest::proptest;

use snapshot::{compress, decompress};

const LOREM_STR: &str = include_str!("lorem.txt");
const ZAPPA_STR: &str = include_str!("zappa.txt");

fn compression(s: &str) {
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
    compression(LOREM_STR);
}

#[test]
fn test_compression_zappa() {
    compression(ZAPPA_STR);
}

proptest! {
    #[test]
    fn prop_check_encode_decode(s in "[a-zA-Z0-9._!~$&'()*+;,=/?:@-]+[a-zA-Z0-9._!~$&'()*+;,=/?:@-]+") {
        compression(&s);
    }
}

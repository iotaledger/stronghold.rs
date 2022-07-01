// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use engine::snapshot::{compress, decompress};
/// Requires Linux, MacOS or WSL to compile.  Use Cargo fuzz and the nightly toolchain.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let compressed = compress(data);
    let decompressed = decompress(&compressed).expect("failed to decompress the data");
    assert!(
        decompressed.as_slice() == data,
        "Data is different between compress and decompress"
    );
});

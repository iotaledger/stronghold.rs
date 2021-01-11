#![no_main]

/// Requires Linux, MacOS or WSL to compile.  Use Cargo fuzz and the nightly toolchain.
use libfuzzer_sys::fuzz_target;
use snapshot::{compress, decompress};

fuzz_target!(|data: &[u8]| {
    let compressed = compress(data);
    let decompressed = decompress(&compressed).expect("failed to decompress the data");
    assert!(
        decompressed.as_slice() == data,
        "Data is different between compress and decompress"
    );
});

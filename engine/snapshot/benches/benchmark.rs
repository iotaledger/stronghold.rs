// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};

use snapshot::{compress, decompress};

const LOREM_STR: &str = include_str!("lorem.txt");

fn invert(s: &str) {
    let compressed = compress(s.as_bytes());

    decompress(&compressed).unwrap();
}

fn bench_compression(c: &mut Criterion) {
    c.bench_function("compress and decompress data", |b| {
        b.iter(|| invert(LOREM_STR));
    });
}

fn bench_compress(c: &mut Criterion) {
    c.bench_function("compress data", |b| {
        b.iter(|| compress(LOREM_STR.as_bytes()));
    });
}

fn bench_decompress(c: &mut Criterion) {
    let compressed = compress(LOREM_STR.as_bytes());

    c.bench_function("decompress data", |b| {
        b.iter(|| decompress(&compressed).unwrap());
    });
}

criterion_group!(benches, bench_compression, bench_compress, bench_decompress);
criterion_main!(benches);

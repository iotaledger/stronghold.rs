// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};

/// Primitve benchmark
pub fn bench_unnamed(c: &mut Criterion) {
    c.bench_function("bench_memory", |b| b.iter(|| 1 + 1));
}

criterion_group!(benches, bench_unnamed);
criterion_main!(benches);

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::Criterion;

/// Primitve benchmark
pub fn bnc_memory_usize(c: &mut Criterion) {
    c.bench_function("bench_memory", |_b| {});
}

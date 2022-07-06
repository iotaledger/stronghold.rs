// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use runtime::{
    locked_memory::LockedMemory,
    memories::{
        frag::FragStrategy,
        noncontiguous_memory::{
            NCConfig::{self, *},
            *,
        },
    },
    utils::random_vec,
};

#[allow(dead_code)]
struct TestStruct {
    id: usize,
    name: String,
}

impl Default for TestStruct {
    fn default() -> Self {
        Self {
            id: 0xFFFF_FFFF_FFFF_FFFF,
            name: "Some TestingStruct".to_owned(),
        }
    }
}

fn bench_ncm_full_ram(c: &mut Criterion) {
    bench_ncm(c, FullRam);
}

fn bench_ncm_full_file(c: &mut Criterion) {
    bench_ncm(c, FullFile);
}

fn bench_ncm_ram_file(c: &mut Criterion) {
    bench_ncm(c, RamAndFile);
}

fn bench_ncm_frag_direct(c: &mut Criterion) {
    bench_ncm(c, FragAllocation(FragStrategy::Direct));
}

fn bench_ncm_frag_map(c: &mut Criterion) {
    bench_ncm(c, FragAllocation(FragStrategy::Map));
}

fn bench_ncm_frag_hybrid(c: &mut Criterion) {
    bench_ncm(c, FragAllocation(FragStrategy::Hybrid));
}

fn bench_ncm(c: &mut Criterion, config: NCConfig) {
    let bench_name = match config {
        FullRam => "NCM full ram",
        FullFile => "NCM full file",
        RamAndFile => "NCM ram and file",
        FragAllocation(frag) => match frag {
            FragStrategy::Direct => "NCM fragment direct",
            FragStrategy::Map => "NCM fragment map",
            FragStrategy::Hybrid => "NCM fragment hybrid",
        },
    };

    let data = random_vec(NC_DATA_SIZE);

    c.bench_function(bench_name, |b| {
        b.iter(|| {
            // Allocate
            let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, config.clone()).expect("error while allocating");

            // Unlock non-contiguous memory few times to refresh the shards
            for _ in 0..10 {
                let _ = ncm.unlock().expect("error while unlocking");
            }
        });
    });
}

criterion_group!(
    benches,
    bench_ncm_full_ram,
    bench_ncm_full_file,
    bench_ncm_ram_file,
    bench_ncm_frag_direct,
    bench_ncm_frag_map,
    bench_ncm_frag_hybrid,
);
criterion_main!(benches);

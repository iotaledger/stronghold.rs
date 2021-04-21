// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod provider;

use criterion::{criterion_group, criterion_main, Criterion};

use engine::{
    cache,
    snapshot::{compress, decompress},
    store::Cache,
    vault::{DbView, Key, RecordHint, RecordId, VaultId},
};

use crate::provider::Provider;

fn bench_vault_write(c: &mut Criterion) {
    c.bench_function("Write to new vault", |b| {
        b.iter(|| {
            let mut view: DbView<Provider> = DbView::new();
            let key0 = Key::random().unwrap();
            let vid0 = VaultId::random::<Provider>().unwrap();
            let rid0 = RecordId::random::<Provider>().unwrap();

            view.init_vault(&key0, vid0).unwrap();

            // write to vault0 and record0
            view.write(
                &key0,
                vid0,
                rid0,
                b"abcdefghijklmnopqrstuvwxyz1234567890",
                RecordHint::new(b"test").unwrap(),
            )
            .unwrap();
        });
    });
}

const LOREM_STR: &str = include_str!("lorem.txt");

fn invert(s: &str) {
    let compressed = compress(s.as_bytes());

    decompress(&compressed).unwrap();
}

fn bench_snapshot_compression(c: &mut Criterion) {
    c.bench_function("compress and decompress data", |b| {
        b.iter(|| invert(LOREM_STR));
    });
}

fn bench_snapshot_compress(c: &mut Criterion) {
    c.bench_function("compress data", |b| {
        b.iter(|| compress(LOREM_STR.as_bytes()));
    });
}

fn bench_snapshot_decompress(c: &mut Criterion) {
    let compressed = compress(LOREM_STR.as_bytes());

    c.bench_function("decompress data", |b| {
        b.iter(|| decompress(&compressed).unwrap());
    });
}

fn bench_store_compression(c: &mut Criterion) {
    let mut cache = Cache::new();

    c.bench_function("Write to cache", |b| {
        b.iter(|| {
            cache.insert(b"test", b"values", None);
        });
    });
}

fn bench_store_compress(c: &mut Criterion) {
    let mut cache = Cache::new();

    cache.insert(b"test".to_vec(), b"values".to_vec(), None);

    c.bench_function("Read from cache", |b| {
        b.iter(|| {
            cache.get(&b"test".to_vec());
        });
    });
}

fn bench_store_decompress(c: &mut Criterion) {
    cache! {
          fn fib(n: u32) -> u32 => {
           match n {
               0 => 1,
               1 => 1,
               _ => fib(n - 1) + fib(n - 2),
            }
          }
    }

    fib(20);

    c.bench_function("Read from Cached function", |b| {
        b.iter(|| {
            FIB_CACHE.lock().unwrap().get(&20);
        });
    });
}

criterion_group!(
    benches,
    bench_snapshot_compression,
    bench_snapshot_compress,
    bench_snapshot_decompress,
    bench_store_compress,
    bench_store_compression,
    bench_store_decompress,
    bench_vault_write
);
criterion_main!(benches);

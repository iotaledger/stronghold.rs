// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use iota_stronghold::{Location, RecordHint, Stronghold};

async fn init_stronghold() -> Stronghold {
    Stronghold::init_stronghold_system(b"path".to_vec(), vec![])
        .await
        .unwrap()
}

fn init_read_vault(stronghold: Stronghold) -> Stronghold {
    let system = actix::System::new();

    for i in 0..30 {
        system
            .block_on(stronghold.write_to_vault(
                Location::generic("test", format!("some_record {}", i)),
                format!("test data {}", i).as_bytes().to_vec(),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ))
            .unwrap()
            .unwrap();
    }

    stronghold
}

fn init_read_snap(stronghold: Stronghold, key_data: &[u8]) -> Stronghold {
    let system = actix::System::new();
    let mut stronghold = init_read_vault(stronghold);

    system
        .block_on(stronghold.write_snapshot(&key_data.to_vec(), Some("bench_read".into()), None))
        .unwrap()
        .unwrap();

    stronghold
}

fn bench_stronghold_write_create(c: &mut Criterion) {
    let system = actix::System::new();

    let stronghold = system.block_on(init_stronghold());

    c.bench_function("write to stronghold while creating vaults", |b| {
        b.iter(|| {
            system
                .block_on(stronghold.write_to_vault(
                    Location::generic("test", "some_record"),
                    b"test data".to_vec(),
                    RecordHint::new(b"test").unwrap(),
                    vec![],
                ))
                .unwrap()
                .unwrap();
        });
    });
}

fn bench_write_snapshot(c: &mut Criterion) {
    let system = actix::System::new();
    let stronghold = system.block_on(init_stronghold());
    let mut stronghold = init_read_vault(stronghold);
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    c.bench_function("Write to snapshot", |b| {
        b.iter(|| system.block_on(stronghold.write_snapshot(&key_data, Some("bench".into()), None)));
    });
}

fn bench_read_from_snapshot(c: &mut Criterion) {
    let system = actix::System::new();
    let stronghold = system.block_on(init_stronghold());
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let mut stronghold = init_read_snap(stronghold, &key_data);

    c.bench_function("Read from snapshot", |b| {
        b.iter(|| system.block_on(stronghold.read_snapshot(&key_data, Some("bench_read".into()), None, None)));
    });
}

fn bench_write_store(c: &mut Criterion) {
    let system = actix::System::new();
    let stronghold = system.block_on(init_stronghold());

    c.bench_function("Bench write to store", |b| {
        b.iter(|| system.block_on(stronghold.write_to_store("test some_key".into(), b"test".to_vec(), None)));
    });
}

fn bench_read_store(c: &mut Criterion) {
    let system = actix::System::new();
    let stronghold = system.block_on(init_stronghold());
    system
        .block_on(stronghold.write_to_store("test some_key".into(), b"test".to_vec(), None))
        .unwrap();

    c.bench_function("Bench read from store", |b| {
        b.iter(|| system.block_on(stronghold.read_from_store("test some_key".into())));
    });
}

criterion_group!(
    benches,
    bench_stronghold_write_create,
    bench_read_from_snapshot,
    bench_write_snapshot,
    bench_write_store,
    bench_read_store
);
criterion_main!(benches);

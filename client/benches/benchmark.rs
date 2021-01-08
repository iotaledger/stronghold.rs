// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use iota_stronghold::{Location, RecordHint, Stronghold};

use riker::actors::*;

use futures::executor::block_on;

fn init_stronghold() -> Stronghold {
    let system = ActorSystem::new().unwrap();

    Stronghold::init_stronghold_system(system, b"path".to_vec(), vec![])
}

fn init_read_vault(stronghold: Stronghold) -> Stronghold {
    for i in 0..30 {
        block_on(stronghold.write_to_vault(
            Location::generic("test", format!("some_record {}", i)),
            format!("test data {}", i).as_bytes().to_vec(),
            RecordHint::new(b"test").unwrap(),
            vec![],
        ));
    }

    stronghold
}

fn init_write_vault(stronghold: Stronghold) -> Stronghold {
    for i in 0..5 {
        block_on(stronghold.write_to_vault(
            Location::counter::<_, usize>("test", Some(i)),
            format!("test data {}", i).as_bytes().to_vec(),
            RecordHint::new(b"test").unwrap(),
            vec![],
        ));
    }

    stronghold
}

fn init_read_snap(stronghold: Stronghold, key_data: Vec<u8>) -> Stronghold {
    let mut stronghold = init_read_vault(stronghold);

    block_on(stronghold.write_all_to_snapshot(key_data, Some("bench_read".into()), None));

    stronghold
}

fn bench_stronghold_write_create(c: &mut Criterion) {
    let stronghold = init_stronghold();

    c.bench_function("write to stronghold while creating vaults", |b| {
        b.iter(|| {
            block_on(stronghold.write_to_vault(
                Location::generic("test", "some_record"),
                b"test data".to_vec(),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ));
        });
    });
}

fn bench_stronghold_write_init(c: &mut Criterion) {
    let stronghold = init_stronghold();

    let stronghold = init_write_vault(stronghold);

    c.bench_function("write to stronghold while initializing records", |b| {
        b.iter(|| {
            block_on(stronghold.write_to_vault(
                Location::counter::<_, usize>("test", black_box(Some(6))),
                b"test data".to_vec(),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ));
        });
    });
}

fn bench_write_snapshot(c: &mut Criterion) {
    let stronghold = init_stronghold();
    let mut stronghold = init_read_vault(stronghold);

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    c.bench_function("Write to snapshot", |b| {
        b.iter(|| {
            block_on(stronghold.write_all_to_snapshot(key_data.clone(), Some("bench".into()), None));
        });
    });
}

fn bench_read_from_snapshot(c: &mut Criterion) {
    let stronghold = init_stronghold();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let mut stronghold = init_read_snap(stronghold, key_data.clone());

    c.bench_function("Read from snapshot", |b| {
        b.iter(|| {
            block_on(stronghold.read_snapshot(
                b"path".to_vec(),
                None,
                key_data.clone(),
                Some("bench_read".into()),
                None,
            ));
        });
    });
}

fn bench_write_store(c: &mut Criterion) {
    let stronghold = init_stronghold();

    c.bench_function("Bench write to store", |b| {
        b.iter(|| block_on(stronghold.write_to_store(Location::generic("test", "some_key"), b"test".to_vec(), None)));
    });
}

fn bench_read_store(c: &mut Criterion) {
    let stronghold = init_stronghold();
    block_on(stronghold.write_to_store(Location::generic("test", "some_key"), b"test".to_vec(), None));

    c.bench_function("Bench read from store", |b| {
        b.iter(|| block_on(stronghold.read_from_store(Location::generic("test", "some_key"))));
    });
}

criterion_group!(
    benches,
    bench_stronghold_write_create,
    bench_stronghold_write_init,
    bench_write_snapshot,
    bench_read_from_snapshot,
    bench_write_store,
    bench_read_store
);
criterion_main!(benches);

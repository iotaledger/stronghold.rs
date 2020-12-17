// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use iota_stronghold::{Location, RecordHint, Stronghold};

use riker::actors::*;

use futures::executor::block_on;

fn bench_stronghold_write_create(c: &mut Criterion) {
    let system = ActorSystem::new().unwrap();

    let stronghold = Stronghold::init_stronghold_system(&system, b"path".to_vec(), vec![]);

    c.bench_function("write to stronghold while creating vaults", |b| {
        b.iter(|| {
            block_on(stronghold.write_data(
                Location::generic("test", "some_record"),
                b"test data".to_vec(),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ));
        });
    });
}

fn bench_stronghold_write_init(c: &mut Criterion) {
    let system = ActorSystem::new().unwrap();
    let stronghold = Stronghold::init_stronghold_system(&system, b"path".to_vec(), vec![]);

    for i in 0..5 {
        block_on(stronghold.write_data(
            Location::counter::<_, usize>("test", Some(i)),
            format!("test data {}", i).as_bytes().to_vec(),
            RecordHint::new(b"test").unwrap(),
            vec![],
        ));
    }

    c.bench_function("write to stronghold while initializing records", |b| {
        b.iter(|| {
            block_on(stronghold.write_data(
                Location::counter::<_, usize>("test", black_box(Some(6))),
                b"test data".to_vec(),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ));
        });
    });
}

fn bench_stronghold_read(c: &mut Criterion) {
    let system = ActorSystem::new().unwrap();
    let stronghold = Stronghold::init_stronghold_system(&system, b"path".to_vec(), vec![]);

    for i in 0..10 {
        block_on(stronghold.write_data(
            Location::generic("test", format!("some_record {}", i)),
            format!("test data {}", i).as_bytes().to_vec(),
            RecordHint::new(b"test").unwrap(),
            vec![],
        ));
    }

    c.bench_function("read from stronghold", |b| {
        b.iter(|| {
            block_on(stronghold.read_data(Location::generic("test", "some_record 5")));
        });
    });
}

criterion_group!(
    benches,
    bench_stronghold_write_create,
    bench_stronghold_read,
    bench_stronghold_write_init
);
criterion_main!(benches);

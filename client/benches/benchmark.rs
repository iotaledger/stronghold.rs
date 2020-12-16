// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};

use iota_stronghold::{RecordHint, Stronghold};

use riker::actors::*;

use futures::executor::block_on;

fn init_stronghold_system_write() -> Stronghold {
    let system = ActorSystem::new().unwrap();
    let stronghold = Stronghold::init_stronghold_system(system, b"path".to_vec(), vec![]);

    stronghold
}

fn bench_stronghold_write(c: &mut Criterion) {
    let stronghold = init_stronghold_system_write();

    c.bench_function("write to stronghold", |b| {
        b.iter(|| {
            block_on(stronghold.write_data(
                b"Some data".to_vec(),
                b"path".to_vec(),
                Some(1),
                RecordHint::new(b"test").unwrap(),
                vec![],
            ));
        });
    });
}

criterion_group!(benches, bench_stronghold_write);
criterion_main!(benches);

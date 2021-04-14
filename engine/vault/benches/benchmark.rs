// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod provider;

use vault::{nvault::DbView, DBView, Key, ReadResult, RecordHint, RecordId, VaultId};

use std::iter::empty;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use crate::provider::Provider;

fn bench_write(c: &mut Criterion) {
    c.bench_function("write to engine", |b| {
        b.iter(|| {
            let k: Key<Provider> = Key::random().unwrap();
            let v0 = DBView::load(k, empty::<ReadResult>()).unwrap();

            let mut writes = vec![];

            let id = RecordId::random::<Provider>().unwrap();
            let mut w = v0.writer(id);
            writes.push(w.truncate().unwrap());

            writes.append(
                &mut w
                    .write(
                        black_box(b"abcdefghijklmnopqrstuvwxyz1234567890"),
                        RecordHint::new(b"test").unwrap(),
                    )
                    .unwrap(),
            );
        });
    });
}

fn bench_nvault_write(c: &mut Criterion) {
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

criterion_group!(benches, bench_write, bench_nvault_write);
criterion_main!(benches);

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod provider;

use vault::{DBView, Key, ReadResult, RecordHint, RecordId};

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

criterion_group!(benches, bench_write);
criterion_main!(benches);

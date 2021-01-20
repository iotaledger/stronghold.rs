// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod provider;

use vault::{DBView, Key, ReadResult, RecordHint, RecordId};

use std::iter::empty;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use crate::provider::Provider;

use runtime::guarded::r#box::GuardedBox;

use secret::Protection;

fn bench_write(c: &mut Criterion) {
    c.bench_function("write to engine", |b| {
        b.iter(|| {
            let k: Key<Provider> = Key::random().unwrap();
            let v0 = DBView::load(k, empty::<ReadResult>()).unwrap();

            let mut writes = vec![];

            let id = RecordId::random::<Provider>().unwrap();
            let mut w = v0.writer(id);
            writes.push(w.truncate().unwrap());

            let (rk, r) = vault::recipient_keypair().unwrap();
            let rk = GuardedBox::new(rk).unwrap();

            writes.append(
                &mut w
                    .write(
                        rk,
                        r.protect(black_box("abcdefghijklmnopqrstuvwxyz1234567890".as_bytes()))
                            .unwrap(),
                        RecordHint::new(b"test").unwrap(),
                    )
                    .unwrap(),
            );
        });
    });
}

criterion_group!(benches, bench_write);
criterion_main!(benches);

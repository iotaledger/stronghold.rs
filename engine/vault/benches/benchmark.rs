// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod provider;

use vault::{vault::DbView, Key, RecordHint, RecordId, VaultId};

use criterion::{criterion_group, criterion_main, Criterion};

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

criterion_group!(benches, bench_vault_write);
criterion_main!(benches);

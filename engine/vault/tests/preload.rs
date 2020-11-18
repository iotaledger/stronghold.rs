// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod utils;

use std::collections::HashMap;

use utils::test_vault::{PlainVault, TestVault};

const DATA: &str = include_str!("data.json");

fn testset(set: &str) {
    let vault = TestVault::from_json(DATA, set);
    let view = vault::DBView::load(vault.key().clone(), vault.list()).unwrap();
    let records: Vec<_> = view.records().collect();

    let reader = view.reader();
    let existing: HashMap<_, _> = records
        .into_iter()
        .map(|(id, hint)| (reader.prepare_read(id).unwrap(), hint))
        .map(|(req, hint)| (vault.read(req).unwrap(), hint))
        .map(|(res, hint)| (hint, reader.read(res).unwrap()))
        .collect();

    let plain = PlainVault::from_json(DATA, set);

    assert_eq!(existing, plain.records);
}

#[test]
fn testset_full() {
    testset("full");
}

#[test]
fn testset_partial() {
    testset("partial")
}

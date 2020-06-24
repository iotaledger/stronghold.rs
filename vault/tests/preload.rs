mod utils;

use std::collections::HashMap;

use utils::test_vault::{PlainVault, TestVault};

const DATA: &str = include_str!("data.json");

fn testset(set: &str) {
    let vault = TestVault::from_json(DATA, set);
    let view = vault::DBView::load(vault.key().clone(), vault.list()).unwrap();
    let entries: Vec<_> = view.entries().collect();

    let reader = view.reader();
    let existing: HashMap<_, _> = entries
        .into_iter()
        .map(|(id, hint)| (reader.prepare_read(id).unwrap(), hint))
        .map(|(ta, hint)| (vault.read(ta).unwrap(), hint))
        .map(|(ta, hint)| (hint, reader.read(ta).unwrap()))
        .collect();

    let plain = PlainVault::from_json(DATA, set);
    assert_eq!(existing, plain.entries);
}

#[test]
fn testset_full() {
    testset("full");
}

#[test]
fn testset_partial() {
    testset("partial")
}

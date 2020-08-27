// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use policy_macros::map;
use std::collections::HashMap;

use policyengine::types::{access::Access, Cardinality};

#[test]
#[allow(dead_code)]
fn test_enum_cardinality() {
    #[derive(Cardinality)]
    enum LocalA {
        A,
        B,
        C,
    }

    #[derive(Cardinality)]
    enum LocalB<T>
    where
        T: Clone + Default,
    {
        A,
        Random,
        SomeValue(usize),
        StructVariant { name: String },
        Generic(T),
    }

    assert_eq!(LocalA::cardinality(), 3);
    assert_eq!(LocalB::<usize>::cardinality(), 5);
    assert_eq!(Access::cardinality(), 5);
}

#[test]
pub fn test_create_map() {
    let mut map_normal = HashMap::new();
    map_normal.insert("key_1", 123);
    map_normal.insert("key_2", 123);
    map_normal.insert("key_3", 321);
    map_normal.insert("key_4", 123);

    let map_macro = map! {
        "key_1" : 123,
        "key_2" : 123,
        "key_3" : 321,
        "key_4" : 123
    };

    assert_eq!(map_normal, map_macro);
}

#[test]
#[should_panic]
pub fn test_create_map_fail() {
    let mut map_normal = HashMap::new();
    map_normal.insert("key_1", 123);
    map_normal.insert("key_2", 123);
    map_normal.insert("key_3", 321);
    map_normal.insert("key_4", 123);

    // This uses an undefined symbol as key, and
    // a different value type. The construction should fail.
    let map_macro = map! {
        "key_1" : 123,
        key_2 : 123,
        "key_3" : String::new(),
        "key_4" : 123
    };

    assert_eq!(map_normal, map_macro);
}

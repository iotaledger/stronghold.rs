// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use macros::{impl_count_tuples, map};
use std::collections::HashMap;

/// Local type that will be implemented by the trait
pub trait Count {
    /// Returns the number of items of an implementor
    fn count(&self) -> usize;
}

// tuple count trait must be called here
impl_count_tuples!(16);

#[test]
pub fn test_tuple_count() {
    assert_eq!((1, 2, 3, 4).count(), 4);
    assert_eq!((1, 2, 3, 4, "string").count(), 5);
    assert_eq!((1, 2, 3, 4, 232.32, 34, 'a', "other string").count(), 8);
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

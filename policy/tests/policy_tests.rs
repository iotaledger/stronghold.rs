// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::panic;
use policyengine::types::AnyMap;

#[derive(Default, PartialEq, Clone)]
pub struct Entity {
    id: usize,
    name: String,
    allowed: Vec<String>,
}

#[test]
fn test_any_map() {
    let mut data = AnyMap::default();

    let entity = Entity {
        id: 0xDEADFEED,
        name: "id:iota:urn:http://resource.com".to_string(),
        allowed: vec!["loc_a".to_string(), "loc_b".to_string()],
    };

    data.insert("key", Box::new(1usize));
    data.insert("key_b", Box::new("hello".to_string()));
    data.insert("entity", Box::new(entity.clone()));

    let number = match data.get::<&usize>("key") {
        Some(n) => n,
        _ => panic!("No value present"),
    };
    let string = match data.get::<&String>("key_b") {
        Some(s) => s,
        _ => panic!("No value present"),
    };
    let actual_entity = match data.get::<&Entity>("entity") {
        Some(r) => r,
        _ => panic!("No value present"),
    };

    assert_eq!(*number, &1usize);
    assert_eq!(*string, &"hello".to_string());

    assert_eq!(actual_entity.id, entity.id);
    assert_eq!(actual_entity.name, entity.name);
    assert_eq!(actual_entity.allowed, entity.allowed);
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod supply;

use std::collections::HashMap;

use policyengine::{
    types::{access::Access, anymap::AnyMap, Cardinality},
    Engine, Policy,
};

use stronghold_utils::random as rnd;

use self::supply::*;
use macros::Cardinality;
use rand::Rng;

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
fn test_policy() {
    // set up
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::default();
    let mut rng = rand::thread_rng();

    let runs = 40;
    let max_locations = 30;

    for _ in 0..runs {
        let peer_id: PeerId = rnd::bytestring(64).into();
        let client_id: ClientId = rnd::bytestring(64).into();

        engine.context(peer_id.clone(), client_id.clone());

        let num_locations = rng.gen_range(1usize..max_locations);

        // create map of expected values
        let expected: HashMap<_, Access> = std::iter::repeat_with(|| (Location::random(), rng.gen()))
            .take(num_locations)
            .collect();

        // configure
        expected.iter().for_each(|(location, access)| {
            engine.insert(client_id.clone(), access.clone(), location.clone());
        });

        // go over locations
        expected.iter().for_each(|(location, access)| {
            // test
            match engine.check_access(&peer_id, location) {
                Ok(ref inner) => {
                    assert_eq!(access, inner);
                }
                Err(_) => {
                    panic!("Location has no access defined")
                }
            }
        });

        // tear down
        engine.clear_all();
    }
}

// todo move to types
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod supply;

#[cfg(test)]
use self::supply::*;
use policyengine::{types::access::Access, Engine, Policy};
use rand::Rng;
use std::collections::HashMap;
use stronghold_utils::random as rnd;

#[test]
fn test_policy_check_forward() {
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::new();

    let peer_a: PeerId = b"peer_a".into();
    let client_a: ClientId = b"client_a".into();

    let peer_b: PeerId = b"peer_b".into();
    let client_b: ClientId = b"client_b".into();

    engine.context(peer_a.clone(), client_a.clone());
    engine.context(peer_b.clone(), client_b.clone());

    // create some access rules
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslaj");
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslajsaxsa");
    engine.insert(client_a.clone(), Access::Write, b"loc:abc");
    engine.insert(client_a, Access::Execute, b"loc:de-fgff");
    engine.insert(client_b.clone(), Access::Write, b"loc:15262537648");
    engine.insert(client_b, Access::Read, b"loc:5454");

    // forward check for access rules
    assert_eq!(engine.check_access(&peer_a, Some(b"loc:kljkslaj")), Ok(Access::Read));
    assert_eq!(
        engine.check_access(&peer_a, Some(b"loc:kljkslajsaxsa")),
        Ok(Access::Read)
    );
    assert_eq!(engine.check_access(&peer_a, Some(b"loc:abc")), Ok(Access::Write));
    assert_eq!(engine.check_access(&peer_a, Some(b"loc:de-fgff")), Ok(Access::Execute));
    assert_eq!(
        engine.check_access(&peer_b, Some(b"loc:15262537648")),
        Ok(Access::Write)
    );
    assert_eq!(engine.check_access(&peer_b, Some(b"loc:5454")), Ok(Access::Read));
}

#[test]
fn test_policy_check_reverse() {
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::new();

    let peer_a: PeerId = b"peer_a".into();
    let client_a: ClientId = b"client_a".into();

    let peer_b: PeerId = b"peer_b".into();
    let client_b: ClientId = b"client_b".into();

    engine.context(peer_a.clone(), client_a.clone());
    engine.context(peer_b.clone(), client_b.clone());

    // create some access rules
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslaj");
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslajsaxsa");
    engine.insert(client_a.clone(), Access::Write, b"loc:abc");
    engine.insert(client_a, Access::Execute, b"loc:de-fgff");
    engine.insert(client_b.clone(), Access::Write, b"loc:15262537648");
    engine.insert(client_b, Access::Read, b"loc:5454");

    // reverse checks
    assert_eq!(
        engine.check(&peer_a, Some(Access::Read)),
        Some(vec![b"loc:kljkslaj".into(), b"loc:kljkslajsaxsa".into()])
    );

    assert_eq!(
        engine.check(&peer_a, Some(Access::Write)),
        Some(vec![b"loc:abc".into()])
    );

    assert_eq!(
        engine.check(&peer_a, Some(Access::Execute)),
        Some(vec![b"loc:de-fgff".into()])
    );

    assert_eq!(
        engine.check(&peer_b, Some(Access::Write)),
        Some(vec![b"loc:15262537648".into()])
    );

    assert_eq!(
        engine.check(&peer_b, Some(Access::Read)),
        Some(vec![b"loc:5454".into()])
    );
}

#[test]
fn test_with_default() {
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::new_with_default(Access::All);

    let peer_a: PeerId = b"peer_a".into();
    let client_a: ClientId = b"client_a".into();

    let peer_b: PeerId = b"peer_b".into();
    let client_b: ClientId = b"client_b".into();

    let peer_c: PeerId = b"peer_c".into();

    engine.context(peer_a, client_a.clone());
    engine.context(peer_b, client_b.clone());

    // create some access rules
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslaj");
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslajsaxsa");
    engine.insert(client_a.clone(), Access::Write, b"loc:abc");
    engine.insert(client_a, Access::Execute, b"loc:de-fgff");
    engine.insert(client_b.clone(), Access::Write, b"loc:15262537648");
    engine.insert(client_b, Access::Read, b"loc:5454");

    // forward check for access rules
    assert_eq!(engine.check_access(&peer_c, None::<Location>), Ok(Access::All));
}

#[test]
fn test_with_default_reset() {
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::new_with_default(Access::All);

    let peer_a: PeerId = b"peer_a".into();
    let client_a: ClientId = b"client_a".into();

    let peer_b: PeerId = b"peer_b".into();
    let client_b: ClientId = b"client_b".into();

    let peer_c: PeerId = b"peer_c".into();

    engine.context(peer_a.clone(), client_a.clone());
    engine.context(peer_b.clone(), client_b.clone());

    // create some access rules
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslaj");
    engine.insert(client_a.clone(), Access::Read, b"loc:kljkslajsaxsa");
    engine.insert(client_a.clone(), Access::Write, b"loc:abc");
    engine.insert(client_a, Access::Execute, b"loc:de-fgff");
    engine.insert(client_b.clone(), Access::Write, b"loc:15262537648");
    engine.insert(client_b, Access::Read, b"loc:5454");

    // forward check for access rules
    assert_eq!(engine.check_access(&peer_c, None::<Location>), Ok(Access::All));

    // reset all
    engine.clear_all();

    // set default
    engine.set_default(Access::NoAccess);

    // check if default access is set
    assert_eq!(engine.check_access(&peer_a, None::<Location>), Ok(Access::NoAccess));
    assert_eq!(engine.check_access(&peer_b, None::<Location>), Ok(Access::NoAccess));
}

#[test]
fn test_policy() {
    // set up
    let mut engine: Engine<PeerId, ClientId, Location> = Engine::new();
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
            match engine.check_access(&peer_id, Some(location.clone())) {
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{
    actors::{GetClient, Registry, RemoveClient, SpawnClient},
    state::{secure::Store, snapshot::Snapshot},
    Location, Provider,
};
use actix::Actor;
use engine::vault::{ClientId, DbView};

#[actix::test]
async fn test_insert_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        let n = registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await;

        assert!(n.is_ok());
    }
}

#[actix::test]
async fn test_get_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        assert!(registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await
            .is_ok());
    }

    assert!(registry
        .send(GetClient {
            id: ClientId::load("b".repeat(24).as_bytes()).unwrap(),
        })
        .await
        .is_ok());
}

#[actix::test]
async fn test_remove_client() {
    let registry = Registry::default().start();

    for d in 'a'..'z' {
        let format_str = format!("{}", d).repeat(24);
        let id_str = format_str.as_str().as_bytes();
        assert!(registry
            .send(SpawnClient {
                id: ClientId::load(id_str).unwrap(),
            })
            .await
            .is_ok());
    }

    if let Ok(result) = registry
        .send(RemoveClient {
            id: ClientId::load("a".repeat(24).as_bytes()).unwrap(),
        })
        .await
    {
        assert!(result.is_ok())
    }
}

#[test]
#[ignore]
#[allow(unused, clippy::type_complexity)]
fn test_snapshot_export() {
    // test specific imports
    use crate::state::snapshot::SnapshotState;
    use engine::vault::{Key as PKey, VaultId};
    use stronghold_utils::random;

    // config
    let key_size = 32;

    // create virtual state
    let client0 = ClientId::random::<Provider>();
    let client1 = ClientId::random::<Provider>();

    let loc0 = Location::generic(b"vid0".to_vec(), b"rid0".to_vec());
    let loc1 = Location::generic(b"vid1".to_vec(), b"rid1".to_vec());
    let loc2 = Location::generic(b"vid2".to_vec(), b"rid2".to_vec());
    let loc3 = Location::generic(b"vid0".to_vec(), b"rid3".to_vec());
    let loc4 = Location::generic(b"vid1".to_vec(), b"rid4".to_vec());
    let loc5 = Location::generic(b"vid2".to_vec(), b"rid5".to_vec());

    let key0: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key0_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    let key1: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key1_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    let key2: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key2_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    let key3: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key3_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    let key4: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key4_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    let key5: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();
    let key5_b: PKey<Provider> = PKey::load(random::bytestring(key_size)).unwrap();

    // create empty state
    let state: HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)> = HashMap::new();

    let store = Store::new();
    let view: DbView<Provider> = DbView::new();
    let mut snapshot = Snapshot::new(SnapshotState(state));

    // fill some values

    // prepare to export entries / location

    let mut entries = HashMap::new();

    entries.insert(loc1, (key0, key0_b));

    // let _exported = snapshot.export(entries);
}

#[test]
fn test_snapshot_difference_shape() {
    // test create the shape of vault entries
}

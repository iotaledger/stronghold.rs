// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    line_error,
    utils::{into_map, LoadFromPath},
    Location, RecordHint, Stronghold,
};

use crypto::macs::hmac::HMAC_SHA512;

use engine::vault::{ClientId, VaultId};

async fn setup_stronghold() -> Stronghold {
    let client_path = b"test".to_vec();

    // we skip initializing the actor system, as it will be started externally
    Stronghold::init_stronghold_system(client_path, vec![]).await.unwrap()
}

// test basic read and write.
#[actix::test]
async fn test_read_write() {
    let stronghold = setup_stronghold().await;
    let client_path = b"test".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);

    stronghold
        .write_to_vault(
            loc0.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").expect(line_error!()),
            vec![],
        )
        .await;

    let (p, _) = stronghold.read_secret(client_path, loc0).await;

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));
}

// test read and write with the counter head.
#[actix::test]
async fn test_head_read_write() {
    let stronghold = setup_stronghold().await;
    let client_path = b"test".to_vec();

    let lochead = Location::counter::<_, usize>("path", 0);

    stronghold
        .write_to_vault(
            lochead.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").expect(line_error!()),
            vec![],
        )
        .await;

    // update on api: test bogus now?
    // let lochead = lochead.increment_counter();

    stronghold
        .write_to_vault(
            lochead.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"second hint").expect(line_error!()),
            vec![],
        )
        .await;

    let (p, _) = stronghold.read_secret(client_path, lochead).await;

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));
}

#[actix::test]
async fn test_multi_write_read_counter_head() {
    let stronghold = setup_stronghold().await;
    let client_path = b"test".to_vec();

    let loc5 = Location::counter::<_, usize>("path", 5);
    let loc15 = Location::counter::<_, usize>("path", 15);
    let loc19 = Location::counter::<_, usize>("path", 19);

    for i in 0..20 {
        let lochead = Location::counter::<_, usize>("path", i);
        let data = format!("test {:?}", i);
        stronghold
            .write_to_vault(
                lochead.clone(),
                data.as_bytes().to_vec(),
                RecordHint::new(data).expect(line_error!()),
                vec![],
            )
            .await;
    }

    let (list, _) = stronghold.list_hints_and_ids("path").await;

    assert_eq!(20, list.len());

    let b = stronghold.record_exists(loc5.clone()).await;
    assert!(b);
    let b = stronghold.record_exists(loc19.clone()).await;
    assert!(b);
    let b = stronghold.record_exists(loc15.clone()).await;
    assert!(b);

    let (p, _) = stronghold.read_secret(client_path.clone(), loc19).await;
    assert_eq!(Some(b"test 19".to_vec()), p);

    let (p, _) = stronghold.read_secret(client_path.clone(), loc5).await;

    assert_eq!(Some(b"test 5".to_vec()), p);

    let (p, _) = stronghold.read_secret(client_path, loc15).await;

    assert_eq!(Some(b"test 15".to_vec()), p);
}

// test delete_data.
#[actix::test]
async fn test_revoke_with_gc() {
    let stronghold = setup_stronghold().await;
    let lochead = Location::counter::<_, usize>("path", 0);
    let client_path = b"test".to_vec();

    for i in 0..10 {
        let lochead = Location::counter::<_, usize>("path", i);

        // update on api: increment counter
        // let lochead = lochead.clone().increment_counter();
        let data = format!("test {:?}", i);
        stronghold
            .write_to_vault(
                lochead.clone(),
                data.as_bytes().to_vec(),
                RecordHint::new(data).expect(line_error!()),
                vec![],
            )
            .await;
    }

    for i in 0..10 {
        let loc = Location::counter::<_, usize>("path", i);

        stronghold.delete_data(loc.clone(), false).await;

        let (p, _) = stronghold.read_secret(client_path.clone(), loc).await;

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));
    }

    let (ids, _res) = stronghold.list_hints_and_ids(lochead.vault_path().to_vec()).await;

    stronghold.garbage_collect(lochead.vault_path().to_vec()).await;

    assert_eq!(ids, vec![]);
}

/// Test writing to a snapshot and reading back.
#[actix::test]
async fn test_write_read_snapshot() {
    let mut stronghold = setup_stronghold().await;

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path = b"test".to_vec();

    for i in 0..20 {
        let loc = Location::counter::<_, usize>("path", i);

        let data = format!("test {:?}", i);
        stronghold
            .write_to_vault(
                loc,
                data.as_bytes().to_vec(),
                RecordHint::new(data).expect(line_error!()),
                vec![],
            )
            .await;
    }

    stronghold
        .write_all_to_snapshot(&key_data, Some("test1".into()), None)
        .await;

    stronghold.kill_stronghold(client_path.clone(), false).await;

    // remark: changed former_client_path from 'None' to 'Some(client_path)'
    stronghold
        .read_snapshot(client_path.clone(), None, &key_data, Some("test1".into()), None)
        .await;

    for i in 0..20 {
        let loc = Location::counter::<_, usize>("path", i);

        let (p, err) = stronghold.read_secret(client_path.clone(), loc).await;

        if let crate::ResultMessage::Error(e) = err {
            println!("Error occured: {}", e)
        }

        let res = format!("test {:?}", i);

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
    }
}

/// Spawn a number of actors and write one record into each of the child actors.  Writes the data from all of the actors
/// into a snapshot. Clears the cache of the actors and then rebuilds them before re-reading the snapshot data back and
/// checking it for consistency.
#[actix::test]
async fn test_write_read_multi_snapshot() {
    let mut stronghold = setup_stronghold().await;
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let num_actors = 20;

    // spawn a number of actors
    for i in 0..num_actors {
        stronghold
            .spawn_stronghold_actor(format!("test {:?}", i).as_bytes().to_vec(), vec![])
            .await;
    }

    // write into vault
    for i in 0..num_actors {
        let data = format!("test {:?}", i);
        let loc = Location::counter::<_, usize>("path", i);

        stronghold
            .switch_actor_target(format!("test {:?}", i).as_bytes().to_vec())
            .await;

        stronghold
            .write_to_vault(
                loc,
                data.as_bytes().to_vec(),
                RecordHint::new(data).expect(line_error!()),
                vec![],
            )
            .await;
    }

    stronghold
        .write_all_to_snapshot(&key_data, Some("test2".into()), None)
        .await;

    for i in 0..num_actors {
        stronghold
            .kill_stronghold(format!("test {:?}", i).as_bytes().to_vec(), false)
            .await;
    }

    for i in 0..num_actors {
        let client_path = format!("test {:?}", i).as_bytes().to_vec();
        stronghold.switch_actor_target(client_path.clone()).await;
        stronghold
            .read_snapshot(client_path, None, &key_data, Some("test2".into()), None)
            .await;
    }

    for i in 0..num_actors {
        let loc = Location::counter::<_, usize>("path", i);
        let local_client_path = format!("test {:?}", i).as_bytes().to_vec();
        stronghold.switch_actor_target(local_client_path.clone()).await;
        let (p, _) = stronghold.read_secret(local_client_path.clone(), loc.clone()).await;
        let res = format!("test {:?}", i);

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
    }
}

#[test]
fn test_pub_private_field_serialization() {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    struct Private {
        a: u64,
        b: String,
        m: BTreeMap<String, u64>,
    }

    impl Private {
        pub fn m(&self) -> &BTreeMap<String, u64> {
            &self.m
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    struct Public {
        pub a: u64,
        pub b: String,
        pub m: BTreeMap<String, u64>,
    }

    impl Public {
        pub fn m(&self) -> &BTreeMap<String, u64> {
            &self.m
        }
    }

    let mut am = BTreeMap::new();
    am.insert("key0".to_string(), 1);
    am.insert("key1".to_string(), 3);
    am.insert("key2".to_string(), 2);
    let a = Private {
        a: 1234,
        b: "hello".to_string(),
        m: am,
    };

    let mut bm = BTreeMap::new();
    bm.insert("key0".to_string(), 1);
    bm.insert("key1".to_string(), 3);
    bm.insert("key2".to_string(), 2);
    let b = Public {
        a: 1234,
        b: "hello".to_string(),
        m: bm,
    };

    let a_ser = bincode::serialize(&a).unwrap();
    let b_ser = bincode::serialize(&b).unwrap();

    assert_eq!(a_ser, b_ser);

    let a_to_b_deser = bincode::deserialize::<Public>(&a_ser).expect("Failed to deserialize");

    assert_eq!(b, a_to_b_deser);
}

#[actix::test]
async fn test_store() {
    let client_path = b"test".to_vec();
    let payload = b"test data";

    let location = Location::generic("some_data", "location");
    let stronghold = Stronghold::init_stronghold_system(client_path, vec![]).await.unwrap();

    stronghold
        .write_to_store(location.clone(), payload.to_vec(), None)
        .await;

    let (res, _) = stronghold.read_from_store(location).await;

    assert_eq!(std::str::from_utf8(&res), Ok("test data"));
}

/// ID Tests.
#[test]
fn test_client_id() {
    let path = b"some_path";
    let data = b"a bunch of random data";
    let mut buf = [0; 64];

    let id = ClientId::load_from_path(data, path).unwrap();

    HMAC_SHA512(data, path, &mut buf);

    let (test, _) = buf.split_at(24);

    assert_eq!(ClientId::load(test).unwrap(), id);
}

#[test]
fn test_vault_id() {
    let path = b"another_path_of_data";
    let data = b"a long sentence for seeding the id with some data and bytes.  Testing to see how long this can be without breaking the hmac";
    let mut buf = [0; 64];

    let id = VaultId::load_from_path(data, path).unwrap();

    HMAC_SHA512(data, path, &mut buf);

    let (test, _) = buf.split_at(24);

    assert_eq!(VaultId::load(test).unwrap(), id);
}

#[test]
fn test_into_map() {
    let v = vec![(1, 2), (3, 4), (5, 6)];
    let m = into_map(v);

    assert_eq!(m.len(), 3);
    assert!(m.contains_key(&1));
    assert!(m.contains_key(&3));
    assert!(m.contains_key(&5));
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ActorError, Location, RecordHint, Stronghold};
use stronghold_utils::random::{self, bytestring};

#[actix::test]
async fn test_stronghold() {
    let vault_path = b"path".to_vec();
    let client_path = b"test".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);
    let loc1 = Location::counter::<_, usize>("path", 1);
    let loc2 = Location::counter::<_, usize>("path", 2);

    let store_loc = bytestring(4096);

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    // clone it, and check for consistency
    let stronghold2 = stronghold.clone();

    // Write at the first record of the vault using Some(0).  Also creates the new vault.
    assert!(stronghold2
        .write_to_vault(
            loc0.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold2
        .read_secret(client_path.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // read head from first reference
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(stronghold
        .write_to_vault(
            loc1.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"another hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold.read_secret(client_path.clone(), loc1.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(stronghold
        .write_to_vault(
            loc2.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"yet another hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    // Read the first record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Read the head record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc1).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = stronghold.list_hints_and_ids(vault_path.clone()).await.unwrap();
    println!("{:?}", ids);

    stronghold
        .delete_data(loc0.clone(), true)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap();

    // attempt to read the first record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert!(p.is_none());

    let ids = stronghold.list_hints_and_ids(vault_path.clone()).await.unwrap();
    println!("{:?}", ids);

    stronghold
        .write_to_store(store_loc.clone(), b"test".to_vec(), None)
        .await
        .unwrap();

    let data = stronghold.read_from_store(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    stronghold.garbage_collect(vault_path).await.unwrap();

    stronghold
        .write_snapshot(&key_data, Some("test0".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold.kill_stronghold(client_path.clone(), true).await.unwrap();

    stronghold
        .read_snapshot(&key_data, Some("test0".into()), None, None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    stronghold
        .spawn_stronghold_actor(client_path.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .load_client(client_path.clone(), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // read head after reading snapshot.

    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let p = stronghold.read_secret(client_path.clone(), loc0).await.unwrap();

    assert!(p.is_none());

    stronghold.kill_stronghold(client_path.clone(), false).await.unwrap();

    let p = stronghold.read_secret(client_path.clone(), loc2).await.unwrap();

    assert!(p.is_none());

    let data = stronghold.read_from_store(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    stronghold.delete_from_store(store_loc.clone()).await.unwrap();

    let data = stronghold.read_from_store(store_loc).await.unwrap();

    assert!(data.is_none());

    stronghold.kill_stronghold(client_path.clone(), true).await.unwrap();

    assert!(matches!(
        stronghold.switch_actor_target(client_path).await,
        Err(ActorError::TargetNotFound)
    ))
}

#[actix::test]
async fn run_stronghold_multi_actors() {
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path0 = b"test a".to_vec();
    let client_path1 = b"test b".to_vec();
    let client_path2 = b"test c".to_vec();
    let client_path3 = b"test d".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);

    let loc2 = Location::counter::<_, usize>("path", 2);
    let loc3 = Location::counter::<_, usize>("path", 3);
    let loc4 = Location::counter::<_, usize>("path", 4);

    let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .spawn_stronghold_actor(client_path1.clone(), vec![])
        .await
        .unwrap();

    stronghold.switch_actor_target(client_path0.clone()).await.unwrap();

    assert!(stronghold
        .write_to_vault(loc0.clone(), b"test".to_vec(), RecordHint::new(b"0").unwrap(), vec![],)
        .await
        .is_ok());

    // read head.
    let p = stronghold
        .read_secret(client_path0.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    stronghold.switch_actor_target(client_path1.clone()).await.unwrap();

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(stronghold
        .write_to_vault(
            loc0.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"1").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold
        .read_secret(client_path1.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    stronghold.switch_actor_target(client_path0.clone()).await.unwrap();

    assert!(stronghold
        .write_to_vault(
            loc0.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"2").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold
        .read_secret(client_path0.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = stronghold.list_hints_and_ids(loc2.vault_path()).await.unwrap();
    println!("actor 0: {:?}", ids);

    stronghold
        .write_snapshot(&key_data.to_vec(), Some("megasnap".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold.switch_actor_target(client_path1.clone()).await.unwrap();

    let ids = stronghold.list_hints_and_ids(loc2.vault_path()).await.unwrap();
    println!("actor 1: {:?}", ids);

    stronghold
        .spawn_stronghold_actor(client_path2.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .read_snapshot(&key_data, Some("megasnap".into()), None, None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    stronghold
        .load_client(client_path2.clone(), Some(client_path1.clone()))
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // client_path2 correct?
    let p = stronghold.read_secret(client_path2.clone(), loc0).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(stronghold
        .write_to_vault(
            loc3.clone(),
            b"a new actor test".to_vec(),
            RecordHint::new(b"2").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold.read_secret(client_path2.clone(), loc3).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

    assert!(stronghold
        .write_to_vault(
            loc4.clone(),
            b"a new actor test again".to_vec(),
            RecordHint::new(b"3").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold.read_secret(client_path2, loc4.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

    let mut ids2 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();

    stronghold.switch_actor_target(client_path1).await.unwrap();

    let mut ids1 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    ids2.sort();
    ids1.sort();

    println!("ids and hints => actor 1: {:?}", ids1);
    println!("ids and hints => actor 2: {:?}", ids2);

    assert_eq!(ids1, ids2);

    stronghold
        .spawn_stronghold_actor(client_path3.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .load_client(client_path3, Some(client_path0.clone()))
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    let mut ids3 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    println!("actor 3: {:?}", ids3);

    stronghold.switch_actor_target(client_path0).await.unwrap();

    let mut ids0 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    println!("actor 0: {:?}", ids0);

    ids0.sort();
    ids3.sort();

    assert_eq!(ids0, ids3);

    // stronghold.system.print_tree();
}

#[actix::test]
async fn test_stronghold_generics() {
    // let sys = ActorSystem::new().unwrap();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path = b"test a".to_vec();

    let slip10_seed = Location::generic("slip10", "seed");

    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    assert!(stronghold
        .write_to_vault(
            slip10_seed.clone(),
            b"AAAAAA".to_vec(),
            RecordHint::new(b"first hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());
    let p = stronghold.read_secret(client_path, slip10_seed).await.unwrap();
    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("AAAAAA"));

    stronghold
        .write_snapshot(&key_data.to_vec(), Some("generic".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));
}

#[actix::test]
async fn test_store_snapshot_key() {
    let key_data: Vec<u8> = random::random::<[u8; 32]>().into();
    let client_path = random::bytestring(1024);

    let loc = Location::counter::<_, usize>("path", 0);
    let data = random::bytestring(1024);
    let snapshot_key_loc = Location::generic(random::string(256), random::string(256));
    let snapshot = "test_store_snapshot_key".to_string();

    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    assert!(stronghold
        .write_to_vault(loc.clone(), data.clone(), RecordHint::new(b"").unwrap(), vec![])
        .await
        .is_ok());

    stronghold
        .store_snapshot_key(&key_data, snapshot_key_loc.clone())
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold
        .write_snapshot_stored_key(snapshot_key_loc, Some(snapshot.clone()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold.kill_stronghold(client_path.clone(), false).await.unwrap();

    stronghold
        .read_snapshot(&key_data, Some(snapshot), None, None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    stronghold
        .load_client(client_path.clone(), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    let p = stronghold.read_secret(client_path, loc).await.unwrap();
    assert_eq!(p.unwrap(), data);
}

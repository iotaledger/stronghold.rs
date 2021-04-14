// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use crate::{line_error, Location, RecordHint, Stronghold};
#[cfg(feature = "communication")]
use crate::{ProcResult, Procedure, ResultMessage, SLIP10DeriveInput, StatusMessage};

#[cfg(feature = "communication")]
use super::fresh;

#[test]
fn test_stronghold() {
    let sys = ActorSystem::new().unwrap();
    let vault_path = b"path".to_vec();
    let client_path = b"test".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);
    let loc1 = Location::counter::<_, usize>("path", 1);
    let loc2 = Location::counter::<_, usize>("path", 2);

    let store_loc = Location::generic("some", "path");

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let mut stronghold = Stronghold::init_stronghold_system(sys, client_path.clone(), vec![]);

    // Write at the first record of the vault using Some(0).  Also creates the new vault.
    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    futures::executor::block_on(stronghold.write_to_vault(
        loc1.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"another hint").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc1.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.write_to_vault(
        loc2.clone(),
        b"yet another test".to_vec(),
        RecordHint::new(b"yet another hint").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    // Read the first record of the vault.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Read the head record of the vault.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc1));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));
    println!("{:?}", ids);

    futures::executor::block_on(stronghold.delete_data(loc0.clone(), true));

    // attempt to read the first record of the vault.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));
    println!("{:?}", ids);

    futures::executor::block_on(stronghold.write_to_store(store_loc.clone(), b"test".to_vec(), None));

    let (data, _) = futures::executor::block_on(stronghold.read_from_store(store_loc.clone()));

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    futures::executor::block_on(stronghold.garbage_collect(vault_path));

    futures::executor::block_on(stronghold.write_all_to_snapshot(&key_data, Some("test0".into()), None));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path.clone(),
        None,
        &key_data,
        Some("test0".into()),
        None,
    ));

    // read head after reading snapshot.

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    futures::executor::block_on(stronghold.kill_stronghold(client_path.clone(), false));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    let (data, _) = futures::executor::block_on(stronghold.read_from_store(store_loc.clone()));

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    futures::executor::block_on(stronghold.delete_from_store(store_loc.clone()));

    let (data, _) = futures::executor::block_on(stronghold.read_from_store(store_loc));

    assert_eq!(std::str::from_utf8(&data), Ok(""));

    futures::executor::block_on(stronghold.kill_stronghold(client_path, true));

    stronghold.system.print_tree();
}

#[test]
fn run_stronghold_multi_actors() {
    let sys = ActorSystem::new().unwrap();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let client_path0 = b"test a".to_vec();
    let client_path1 = b"test b".to_vec();
    let client_path2 = b"test c".to_vec();
    let client_path3 = b"test d".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);

    let loc2 = Location::counter::<_, usize>("path", 2);
    let loc3 = Location::counter::<_, usize>("path", 3);
    let loc4 = Location::counter::<_, usize>("path", 4);

    let mut stronghold = Stronghold::init_stronghold_system(sys, client_path0.clone(), vec![]);

    futures::executor::block_on(stronghold.spawn_stronghold_actor(client_path1.clone(), vec![]));

    futures::executor::block_on(stronghold.switch_actor_target(client_path0.clone()));

    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"test".to_vec(),
        RecordHint::new(b"0").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    futures::executor::block_on(stronghold.switch_actor_target(client_path1.clone()));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"1").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.switch_actor_target(client_path0.clone()));

    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"yet another test".to_vec(),
        RecordHint::new(b"2").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc2.vault_path()));
    println!("actor 0: {:?}", ids);

    futures::executor::block_on(stronghold.write_all_to_snapshot(&key_data.to_vec(), Some("megasnap".into()), None));

    futures::executor::block_on(stronghold.switch_actor_target(client_path1.clone()));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc2.vault_path()));
    println!("actor 1: {:?}", ids);

    futures::executor::block_on(stronghold.spawn_stronghold_actor(client_path2.clone(), vec![]));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path2,
        Some(client_path1.clone()),
        &key_data,
        Some("megasnap".into()),
        None,
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.write_to_vault(
        loc3.clone(),
        b"a new actor test".to_vec(),
        RecordHint::new(b"2").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc3));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

    futures::executor::block_on(stronghold.write_to_vault(
        loc4.clone(),
        b"a new actor test again".to_vec(),
        RecordHint::new(b"3").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc4.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

    let (mut ids2, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc4.vault_path()));

    futures::executor::block_on(stronghold.switch_actor_target(client_path1));

    let (mut ids1, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc4.vault_path()));
    ids2.sort();
    ids1.sort();

    assert_eq!(ids1, ids2);

    println!("actor 2: {:?}", ids2);
    println!("actor 1: {:?}", ids1);

    futures::executor::block_on(stronghold.spawn_stronghold_actor(client_path3.clone(), vec![]));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path3,
        Some(client_path0.clone()),
        &key_data,
        Some("megasnap".into()),
        None,
    ));

    let (mut ids3, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc4.vault_path()));
    println!("actor 3: {:?}", ids3);

    futures::executor::block_on(stronghold.switch_actor_target(client_path0));

    let (mut ids0, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc4.vault_path()));
    println!("actor 0: {:?}", ids0);

    ids0.sort();
    ids3.sort();

    assert_eq!(ids0, ids3);

    stronghold.system.print_tree();
}

#[test]
fn test_stronghold_generics() {
    let sys = ActorSystem::new().unwrap();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path = b"test a".to_vec();

    let slip10_seed = Location::generic("slip10", "seed");

    let mut stronghold = Stronghold::init_stronghold_system(sys, client_path, vec![]);

    futures::executor::block_on(stronghold.write_to_vault(
        slip10_seed.clone(),
        b"AAAAAA".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));
    let (p, _) = futures::executor::block_on(stronghold.read_secret(slip10_seed));
    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("AAAAAA"));

    futures::executor::block_on(stronghold.write_all_to_snapshot(&key_data.to_vec(), Some("generic".into()), None));
}

#[cfg(feature = "communication")]
#[test]
fn test_communication() {
    let local_sys = ActorSystem::new().unwrap();
    let local_client = b"local".to_vec();
    let mut local_stronghold = Stronghold::init_stronghold_system(local_sys, local_client, vec![]);
    local_stronghold.spawn_communication();

    let remote_sys = ActorSystem::new().unwrap();
    let remote_client = b"remote".to_vec();
    let mut remote_stronghold = Stronghold::init_stronghold_system(remote_sys, remote_client, vec![]);
    remote_stronghold.spawn_communication();
    if let StatusMessage::Error(_) = futures::executor::block_on(remote_stronghold.allow_all_requests(vec![], true)) {
        panic!("Could not configure firewall.")
    }

    let addr = match futures::executor::block_on(remote_stronghold.start_listening(None)) {
        ResultMessage::Ok(addr) => addr,
        ResultMessage::Error(_) => panic!("Could not start listening"),
    };

    let (peer_id, listeners) = match futures::executor::block_on(remote_stronghold.get_swarm_info()) {
        ResultMessage::Ok((peer_id, listeners, _)) => (peer_id, listeners),
        ResultMessage::Error(_) => panic!("Could not get swarm info."),
    };

    assert!(listeners.as_slice().contains(&addr));

    match futures::executor::block_on(local_stronghold.add_peer(peer_id, Some(addr), None)) {
        ResultMessage::Ok(_) => {}
        ResultMessage::Error(_) => panic!("Could not establish connection to remote."),
    }

    // test writing at remote and reading it from local stronghold
    let loc = Location::counter::<_, usize>("path", 0);
    let original_data = b"some data".to_vec();
    match futures::executor::block_on(remote_stronghold.write_to_store(loc.clone(), original_data.clone(), None)) {
        StatusMessage::OK => {}
        StatusMessage::Error(_) => panic!("Could not write store."),
    }
    let payload = match futures::executor::block_on(local_stronghold.read_from_remote_store(peer_id, loc)) {
        (payload, StatusMessage::OK) => payload,
        (_, StatusMessage::Error(_)) => panic!("Could not read from remote store."),
    };
    assert_eq!(payload, original_data);

    // test writing from local and reading it at remote
    let loc = Location::counter::<_, usize>("path", 1);
    let original_data = b"some second data".to_vec();
    match futures::executor::block_on(local_stronghold.write_to_remote_store(
        peer_id,
        loc.clone(),
        original_data.clone(),
        None,
    )) {
        StatusMessage::OK => {}
        StatusMessage::Error(_) => panic!("Could not write to remote store"),
    }
    let payload = match futures::executor::block_on(remote_stronghold.read_from_store(loc)) {
        (payload, StatusMessage::OK) => payload,
        (_, StatusMessage::Error(_)) => panic!("Could not read from store."),
    };
    assert_eq!(payload, original_data);

    // test writing and reading from local
    let loc = Location::counter::<_, usize>("path", 2);
    let original_data = b"some third data".to_vec();
    match futures::executor::block_on(local_stronghold.write_to_remote_store(
        peer_id,
        loc.clone(),
        original_data.clone(),
        None,
    )) {
        StatusMessage::OK => {}
        StatusMessage::Error(_) => panic!("Could not write to remote store."),
    }
    let payload = match futures::executor::block_on(local_stronghold.read_from_remote_store(peer_id, loc)) {
        (payload, StatusMessage::OK) => payload,
        (_, StatusMessage::Error(_)) => panic!("Could not read from remote store."),
    };
    assert_eq!(payload, original_data);

    // test procedure execution

    let seed = fresh::location();

    match futures::executor::block_on(remote_stronghold.runtime_exec(Procedure::SLIP10Generate {
        size_bytes: None,
        output: seed.clone(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let (_path, chain) = fresh::hd_path();
    let procedure = Procedure::SLIP10Derive {
        chain,
        input: SLIP10DeriveInput::Seed(seed),
        output: fresh::location(),
        hint: fresh::record_hint(),
    };

    match futures::executor::block_on(local_stronghold.remote_runtime_exec(peer_id, procedure)) {
        ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => {}
        ProcResult::Error(err) => panic!("Procedure failed: {:?}", err),
        r => panic!("unexpected result: {:?}", r),
    };
}

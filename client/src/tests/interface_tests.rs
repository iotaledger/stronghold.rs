// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use crate::{
    hd, line_error, Location, ProcResult, Procedure, RecordHint, ResultMessage, SLIP10DeriveInput, StatusMessage,
    Stronghold,
};

#[test]
fn test_stronghold() {
    let sys = ActorSystem::new().unwrap();
    let vault_path = b"path".to_vec();
    let client_path = b"test".to_vec();

    let loc0 = Location::counter::<_, usize>("path", Some(0));
    let loc1 = Location::counter::<_, usize>("path", Some(1));
    let loc2 = Location::counter::<_, usize>("path", Some(2));
    let lochead = Location::counter::<_, usize>("path", None);
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
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    futures::executor::block_on(stronghold.write_to_vault(
        loc1.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"another hint").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.write_to_vault(
        loc2.clone(),
        b"yet another test".to_vec(),
        RecordHint::new(b"yet another hint").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

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

    futures::executor::block_on(stronghold.delete_data(loc0.clone(), false));

    // attempt to read the first record of the vault.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));
    println!("{:?}", ids);

    futures::executor::block_on(stronghold.write_to_store(store_loc.clone(), b"test".to_vec(), None));

    let (data, _) = futures::executor::block_on(stronghold.read_from_store(store_loc.clone()));

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    futures::executor::block_on(stronghold.garbage_collect(vault_path));

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), Some("test0".into()), None));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path.clone(),
        None,
        key_data,
        Some("test0".into()),
        None,
    ));

    // read head after reading snapshot.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    futures::executor::block_on(stronghold.kill_stronghold(client_path.clone(), false));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

    let (data, _) = futures::executor::block_on(stronghold.read_from_store(store_loc));

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

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

    let loc0 = Location::counter::<_, usize>("path", Some(0));
    let lochead = Location::counter::<_, usize>("path", None);

    let mut stronghold = Stronghold::init_stronghold_system(sys, client_path0.clone(), vec![]);

    stronghold.spawn_stronghold_actor(client_path1.clone(), vec![]);

    stronghold.switch_actor_target(client_path0.clone());

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"test".to_vec(),
        RecordHint::new(b"1").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    stronghold.switch_actor_target(client_path1.clone());

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"1").expect(line_error!()),
        vec![],
    ));

    // read head.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    stronghold.switch_actor_target(client_path0.clone());

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"yet another test".to_vec(),
        RecordHint::new(b"2").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
    println!("actor 0: {:?}", ids);

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.to_vec(), Some("megasnap".into()), None));

    stronghold.switch_actor_target(client_path1.clone());

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
    println!("actor 1: {:?}", ids);

    stronghold.spawn_stronghold_actor(client_path2.clone(), vec![]);

    futures::executor::block_on(stronghold.read_snapshot(
        client_path2,
        Some(client_path1.clone()),
        key_data.clone(),
        Some("megasnap".into()),
        None,
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"a new actor test".to_vec(),
        RecordHint::new(b"2").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

    futures::executor::block_on(stronghold.write_to_vault(
        lochead.clone(),
        b"a new actor test again".to_vec(),
        RecordHint::new(b"3").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_secret(lochead.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

    let (ids2, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));

    stronghold.switch_actor_target(client_path1);

    let (ids1, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
    assert_ne!(ids2, ids1);

    println!("actor 2: {:?}", ids2);
    println!("actor 1: {:?}", ids1);

    stronghold.spawn_stronghold_actor(client_path3.clone(), vec![]);

    futures::executor::block_on(stronghold.read_snapshot(
        client_path3,
        Some(client_path0.clone()),
        key_data,
        Some("megasnap".into()),
        None,
    ));

    let (mut ids3, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
    println!("actor 3: {:?}", ids3);

    stronghold.switch_actor_target(client_path0);

    let (mut ids0, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
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

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.to_vec(), Some("generic".into()), None));
}

#[test]
fn test_counters() {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let loc0 = Location::counter::<_, usize>("path", Some(0));
    let loc1 = Location::counter::<_, usize>("path", Some(1));
    let loc2 = Location::counter::<_, usize>("path", Some(2));

    let mut stronghold = Stronghold::init_stronghold_system(sys, client_path.clone(), vec![]);

    // let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    // println!("{:?}", std::str::from_utf8(&p.unwrap()));

    // let (p, _) = futures::executor::block_on(stronghold.read_secret(loc1.clone()));

    // println!("{:?}", std::str::from_utf8(&p.unwrap()));

    futures::executor::block_on(stronghold.write_to_vault(
        loc0.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    // read 0.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc0.clone()));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), None, None));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path.clone(),
        Some(client_path.clone()),
        key_data.clone(),
        None,
        None,
    ));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc0.vault_path()));
    println!("{:?}", ids);

    futures::executor::block_on(stronghold.write_to_vault(
        loc1.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"second hint").expect(line_error!()),
        vec![],
    ));

    // read 1.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc1));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), None, None));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path.clone(),
        Some(client_path.clone()),
        key_data.clone(),
        None,
        None,
    ));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc0.vault_path()));
    println!("{:?}", ids);

    futures::executor::block_on(stronghold.write_to_vault(
        loc2.clone(),
        b"yet another test".to_vec(),
        RecordHint::new(b"third hint").expect(line_error!()),
        vec![],
    ));

    // read 2.
    let (p, _) = futures::executor::block_on(stronghold.read_secret(loc2));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), None, None));

    futures::executor::block_on(stronghold.read_snapshot(
        client_path.clone(),
        Some(client_path),
        key_data.clone(),
        None,
        None,
    ));

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data, None, None));

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(loc0.vault_path()));
    println!("{:?}", ids);
}

#[test]
fn test_crypto() {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();

    let slip10_seed = Location::generic("slip10", "seed");
    let slip10_key = Location::generic("slip10", "key");
    let bip39_seed = Location::generic("bip39", "seed");

    let stronghold = Stronghold::init_stronghold_system(sys, client_path, vec![]);

    match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10Generate {
        output: slip10_seed.clone(),
        hint: RecordHint::new(b"test_seed").expect(line_error!()),
        size_bytes: 32,
    })) {
        ProcResult::SLIP10Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10Derive {
        chain: hd::Chain::from_u32_hardened(vec![]),
        input: SLIP10DeriveInput::Seed(slip10_seed.clone()),
        output: slip10_key,
        hint: RecordHint::new(b"test").expect(line_error!()),
    })) {
        ProcResult::SLIP10Derive(ResultMessage::Ok(key)) => {
            println!("public key: {:?}", key);
        }
        r => panic!("unexpected result: {:?}", r),
    }

    let pk = match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10DeriveAndEd25519PublicKey {
        path: "".into(),
        seed: slip10_seed.clone(),
    })) {
        ProcResult::SLIP10DeriveAndEd25519PublicKey(ResultMessage::Ok(pk)) => {
            crypto::ed25519::PublicKey::from_compressed_bytes(pk).expect(line_error!())
        }
        r => panic!("unexpected result: {:?}", r),
    };

    let msg = b"foobar";
    let sig = match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10DeriveAndEd25519Sign {
        path: "".into(),
        seed: slip10_seed.clone(),
        msg: msg.to_vec(),
    })) {
        ProcResult::SLIP10DeriveAndEd25519Sign(ResultMessage::Ok(sig)) => crypto::ed25519::Signature::from_bytes(sig),
        r => panic!("unexpected result: {:?}", r),
    };

    assert!(crypto::ed25519::verify(&pk, &sig, msg));

    match futures::executor::block_on(stronghold.runtime_exec(Procedure::BIP39Recover {
        output: bip39_seed.clone(),
        hint: RecordHint::new(b"bip_seed").expect(line_error!()),
        mnemonic: "loyal arctic acid useless problem season gate token bunker want human laptop humble gold brand near attract wine arena very vague summer discover pass".into(),
        passphrase: Some("a passphrase".into()),
    })) {
        ProcResult::BIP39Recover(StatusMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(slip10_seed.vault_path()));
    println!("{:?}", ids);

    let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(bip39_seed.vault_path()));
    println!("{:?}", ids);
}

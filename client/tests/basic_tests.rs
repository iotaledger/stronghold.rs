// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

mod fresh;

use iota_stronghold::{line_error, Location, ProcResult, Procedure, RecordHint, ResultMessage, Stronghold, StatusMessage, SLIP10DeriveInput};

use bee_signing_ext::{
    binary::{
        ed25519::{Ed25519PrivateKey, Ed25519Seed},
        BIP32Path,
    },
    Signer,
};

fn setup_stronghold() -> Stronghold {
    let sys = ActorSystem::new().unwrap();

    let client_path = b"test".to_vec();

    Stronghold::init_stronghold_system(sys, client_path, vec![])
}

// test basic read and write.
#[test]
fn test_read_write() {
    let stronghold = setup_stronghold();

    let loc0 = Location::counter::<_, usize>("path", Some(0));

    futures::executor::block_on(stronghold.write_data(
        loc0.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_data(loc0));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));
}

// test read and write with the counter head.
#[test]
fn test_head_read_write() {
    let stronghold = setup_stronghold();

    let lochead = Location::counter::<_, usize>("path", None);

    futures::executor::block_on(stronghold.write_data(
        lochead.clone(),
        b"test".to_vec(),
        RecordHint::new(b"first hint").expect(line_error!()),
        vec![],
    ));

    futures::executor::block_on(stronghold.write_data(
        lochead.clone(),
        b"another test".to_vec(),
        RecordHint::new(b"second hint").expect(line_error!()),
        vec![],
    ));

    let (p, _) = futures::executor::block_on(stronghold.read_data(lochead));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));
}

#[test]
fn test_multi_write_read_counter_head() {
    let stronghold = setup_stronghold();

    let lochead = Location::counter::<_, usize>("path", None);
    let loc5 = Location::counter::<_, usize>("path", Some(5));
    let loc15 = Location::counter::<_, usize>("path", Some(15));

    for i in 0..20 {
        futures::executor::block_on(async {
            let data = format!("test {:?}", i);
            stronghold
                .write_data(
                    lochead.clone(),
                    data.as_bytes().to_vec(),
                    RecordHint::new(data).expect(line_error!()),
                    vec![],
                )
                .await;
        });
    }

    let (p, _) = futures::executor::block_on(stronghold.read_data(lochead));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test 19"));

    let (p, _) = futures::executor::block_on(stronghold.read_data(loc5));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test 5"));

    let (p, _) = futures::executor::block_on(stronghold.read_data(loc15));

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test 15"));
}

// test delete_data.
#[test]
fn test_revoke_with_gc() {
    let stronghold = setup_stronghold();

    let lochead = Location::counter::<_, usize>("path", None);

    for i in 0..10 {
        futures::executor::block_on(async {
            let data = format!("test {:?}", i);
            stronghold
                .write_data(
                    lochead.clone(),
                    data.as_bytes().to_vec(),
                    RecordHint::new(data).expect(line_error!()),
                    vec![],
                )
                .await;
        });
    }

    for i in 0..10 {
        futures::executor::block_on(async {
            let loc = Location::counter::<_, usize>("path", Some(i));

            stronghold.delete_data(loc.clone(), false).await;

            let (p, _) = stronghold.read_data(loc).await;

            assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));
        })
    }

    futures::executor::block_on(stronghold.garbage_collect(lochead.vault_path().to_vec()));

    let ids = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path().to_vec()));

    assert_eq!(ids, (vec![], ResultMessage::Ok(())));
}

/// Test writing to a snapshot and reading back.
#[test]
fn test_write_read_snapshot() {
    let mut stronghold = setup_stronghold();

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let lochead = Location::counter::<_, usize>("path", None);

    let client_path = b"test".to_vec();

    for i in 0..20 {
        futures::executor::block_on(async {
            let data = format!("test {:?}", i);
            stronghold
                .write_data(
                    lochead.clone(),
                    data.as_bytes().to_vec(),
                    RecordHint::new(data).expect(line_error!()),
                    vec![],
                )
                .await;
        });
    }

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), Some("test1".into()), None));

    futures::executor::block_on(stronghold.kill_stronghold(client_path.clone(), false));

    futures::executor::block_on(stronghold.read_snapshot(client_path, None, key_data, Some("test1".into()), None));

    for i in 0..20 {
        futures::executor::block_on(async {
            let loc = Location::counter::<_, usize>("path", Some(i));
            let (p, _) = stronghold.read_data(loc).await;

            let res = format!("test {:?}", i);

            assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
        });
    }
}

/// Makes 11 actors and writes one record into each of the child actors.  Writes the data from all of the actors into a
/// snapshot. Clears the cache of the actors and then rebuilds them before re-reading the snapshot data back and
/// checking it for consistency.
#[test]
fn test_write_read_multi_snapshot() {
    let mut stronghold = setup_stronghold();

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let lochead = Location::counter::<_, usize>("path", None);

    for i in 0..10 {
        stronghold.spawn_stronghold_actor(format!("test {:?}", i).as_bytes().to_vec(), vec![]);
    }

    for i in 0..10 {
        futures::executor::block_on(async {
            let data = format!("test {:?}", i);

            stronghold.switch_actor_target(format!("test {:?}", i).as_bytes().to_vec());

            stronghold
                .write_data(
                    lochead.clone(),
                    data.as_bytes().to_vec(),
                    RecordHint::new(data).expect(line_error!()),
                    vec![],
                )
                .await;
        });
    }

    futures::executor::block_on(stronghold.write_all_to_snapshot(key_data.clone(), Some("test2".into()), None));

    for i in 0..10 {
        futures::executor::block_on(stronghold.kill_stronghold(format!("test {:?}", i).as_bytes().to_vec(), false));
    }

    for i in 0..10 {
        futures::executor::block_on(stronghold.read_snapshot(
            format!("test {:?}", i).as_bytes().to_vec(),
            None,
            key_data.clone(),
            Some("test2".into()),
            None,
        ));
    }

    for i in 0..10 {
        futures::executor::block_on(async {
            stronghold.switch_actor_target(format!("test {:?}", i % 10).as_bytes().to_vec());

            let (p, _) = stronghold.read_data(lochead.clone()).await;

            let res = format!("test {:?}", i);

            assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(res.as_str()));
        });
    }
}

#[test]
fn test_unlock_block() {
    let sys = ActorSystem::new().unwrap();

    let client_path = fresh::bytestring();

    let blip39_seed = Location::generic("blip39", "seed");

    let stronghold = Stronghold::init_stronghold_system(sys, client_path, vec![]);

    let essence = fresh::bytestring();

    match futures::executor::block_on(stronghold.runtime_exec(Procedure::BIP39Generate {
        passphrase: None,
        output: blip39_seed.clone(),
        hint: RecordHint::new(b"test_seed").expect(line_error!()),
    })) {
        ProcResult::BIP39Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    let (seed_data, _) = futures::executor::block_on(stronghold.read_data(blip39_seed.clone()));

    let mut seed_data = seed_data.expect(line_error!());

    let key0 = match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10DeriveAndEd25519PublicKey {
        path: "m/1'".into(),
        seed: blip39_seed.clone(),
    })) {
        ProcResult::SLIP10DeriveAndEd25519PublicKey(ResultMessage::Ok(key)) => key,
        r => panic!("unexpected result: {:?}", r),
    };

    let sig0 = match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10DeriveAndEd25519Sign {
        path: "m/1'".into(),
        seed: blip39_seed.clone(),
        msg: essence.to_vec(),
    })) {
        ProcResult::SLIP10DeriveAndEd25519Sign(ResultMessage::Ok(sig)) => sig,
        r => panic!("unexpected result: {:?}", r),
    };

    let (sig1, key1) = match futures::executor::block_on(stronghold.runtime_exec(Procedure::SignUnlockBlock {
        seed: blip39_seed,
        path: "m/1'".into(),
        essence: essence.to_vec(),
    })) {
        ProcResult::SignUnlockBlock(ResultMessage::Ok((sig, key))) => {
            let sig = crypto::ed25519::Signature::from_bytes(sig);
            let key = crypto::ed25519::PublicKey::from_compressed_bytes(key).unwrap();

            (sig, key)
        }
        r => panic!("unexpected result: {:?}", r),
    };

    if seed_data.len() < 32 {
        todo!("return error message: insufficient bytes")
    }
    seed_data.truncate(32);
    let mut bs = [0; 32];
    bs.copy_from_slice(&seed_data);
    let seed = Ed25519Seed::from_bytes(&seed_data).expect(line_error!());

    let sk = Ed25519PrivateKey::generate_from_seed(&seed, &BIP32Path::from_str("m/1'").unwrap()).expect(line_error!());
    let pk = sk.generate_public_key().to_bytes();
    let sig2 = sk.sign(&essence);

    assert_eq!(key1.to_compressed_bytes(), pk);
    assert_eq!(sig2.to_bytes(), sig1.to_bytes());
    assert_eq!(sig0, sig1.to_bytes());
    assert_eq!(key0, pk);

    assert!(crypto::ed25519::verify(&key1, &sig1, &essence));

    let sc = iota_stronghold::hd::Seed::from_bytes(&seed_data);
    let mkc = sc.to_master_key();
    let skc = mkc
        .derive(&iota_stronghold::hd::Chain::from_u32_hardened(vec![1]))
        .unwrap()
        .secret_key()
        .unwrap();
    let pkc = skc.public_key();
    assert_eq!(pkc.to_compressed_bytes(), pk);
    let sigc = skc.sign(&essence);
    assert_eq!(sigc.to_bytes(), sig0);
}

#[test]
fn test_ed25519_public_key_equivalence() {
    let sh = Stronghold::init_stronghold_system(ActorSystem::new().unwrap(), fresh::bytestring(), vec![]);

    let seed = fresh::location();

    match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Generate {
        output: seed.clone(),
        hint: fresh::record_hint(),
        size_bytes: 32,
    })) {
        ProcResult::SLIP10Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    let (path, chain) = fresh::hd_path();

    let pk0 =
        match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10DeriveAndEd25519PublicKey {
            path,
            seed: seed.clone(),
        })) {
            ProcResult::SLIP10DeriveAndEd25519PublicKey(ResultMessage::Ok(pk)) => pk,
            r => panic!("unexpected result: {:?}", r),
        };

    let pk1 = {
        let key = fresh::location();
        match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
            chain,
            input: SLIP10DeriveInput::Seed(seed),
            output: key.clone(),
            hint: fresh::record_hint(),
        })) {
            ProcResult::SLIP10Derive(StatusMessage::Ok(())) => (),
            r => panic!("unexpected result: {:?}", r),
        };

        match futures::executor::block_on(sh.runtime_exec(Procedure::Ed25519PublicKey {
            private_key: key
        })) {
            ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk)) => pk,
            r => panic!("unexpected result: {:?}", r),
        }
    };

    assert_eq!(pk0, pk1);
}

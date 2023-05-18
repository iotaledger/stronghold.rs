// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_stronghold::{
    procedures::{GenerateKey, KeyType, PublicKey, StrongholdProcedure},
    KeyProvider, Location, SnapshotPath, Stronghold,
};
use std::{error::Error, sync::mpsc::channel};
use threadpool::ThreadPool;
use zeroize::Zeroizing;

const NB_THREADS: usize = 10;

// Create multiple clients and for each insert multiple inputs in their store
// Then check the store content of each client
#[test]
fn test_stronghold_multithreaded_safety() {
    const NB_CLIENTS: usize = 20;
    const NB_INPUTS: usize = 500;

    let main_stronghold = Stronghold::default();
    let pool = ThreadPool::new(NB_THREADS);

    for i in 0..NB_CLIENTS {
        let stronghold = main_stronghold.clone();
        pool.execute(move || {
            let path = format!("client_path{}", i);
            stronghold.create_client(&path).unwrap();
            stronghold.write_client(&path).unwrap();
            for j in 0..NB_INPUTS {
                let cl = stronghold.get_client(&path).unwrap();
                let key = format!("key{}{}", i, j).into_bytes();
                let value = format!("value{}{}", i, j).into_bytes();
                cl.store().insert(key, value, None).unwrap();
            }
            stronghold.write_client(&path).unwrap();
        });
    }
    pool.join();

    for i in 0..NB_CLIENTS {
        let path = format!("client_path{}", i);
        let cl = main_stronghold.get_client(path).unwrap();
        for j in 0..NB_INPUTS {
            let key = format!("key{}{}", i, j).into_bytes();
            let expected_value = format!("value{}{}", i, j).into_bytes();
            let value = cl.store().get(&key).unwrap().unwrap();
            assert_eq!(value, expected_value);
        }
    }
}

// With a single client repeat multiple times:
// - Loop n times:
//   - Create a new public key in the vault
//   - Save the client state into a snapshot file
// - Reset the stronghold instance
// - Load client from snapshot
// - Check that all the secrets that were generated concurrently before are present in the saved state
#[test]
fn test_full_stronghold_access_multithreaded() {
    const NB_INPUTS: usize = 100;
    let pool = ThreadPool::new(NB_THREADS);

    let stronghold = Stronghold::default();
    let snapshot_path: SnapshotPath = SnapshotPath::named("testing-snapshot.snapshot");
    let key = Zeroizing::new(b"abcdefghijklmnopqrstuvwxyz123456".to_vec());
    let vault_path = b"vault_path".to_vec();
    let client_path = b"client_path".to_vec();
    stronghold.create_client(client_path.clone()).unwrap();

    let (tx, rx) = channel();

    for i in 0..NB_INPUTS {
        let key_provider = KeyProvider::try_from(key.clone())
            .map_err(|e| format!("Error {:?}", e))
            .unwrap();
        let tx = tx.clone();
        let stg = stronghold.clone();
        let spath = snapshot_path.clone();
        let cpath = client_path.clone();
        let vpath = vault_path.clone();
        let rpath = format!("record_path{}", i).into_bytes();
        pool.execute(move || {
            let res = test_full_stronghold_access(stg, spath, cpath, vpath, rpath, key_provider);
            tx.send((i, res.unwrap())).expect("Failed to send data through channel");
        });
    }
    pool.join();

    // Collect public keys derived from secrets
    let mut pub_keys: Vec<Option<Vec<u8>>> = (0..NB_INPUTS).map(|_| None).collect();
    for _ in 0..NB_INPUTS {
        let msg = rx.try_recv();
        assert!(msg.is_ok());
        let (i, pub_key) = msg.unwrap();
        pub_keys[i] = Some(pub_key);
    }

    let stronghold = stronghold.reset();
    let key_provider = KeyProvider::try_from(key)
        .map_err(|e| format!("Error {:?}", e))
        .unwrap();
    let client = stronghold
        .load_client_from_snapshot(client_path, &key_provider, &snapshot_path)
        .unwrap();

    // Derive a new public key for each secret
    for (i, pub_key) in pub_keys.iter().enumerate() {
        let rpath = format!("record_path{}", i).into_bytes();
        let loc = crate::Location::generic(vault_path.clone(), rpath);

        let public_key_procedure = PublicKey {
            ty: KeyType::Ed25519,
            private_key: loc,
        };
        let proc = StrongholdProcedure::PublicKey(public_key_procedure);
        let procedure_result = client.clone().execute_procedure(proc).unwrap();
        let new_pub_key: Vec<u8> = procedure_result.into();
        assert_eq!(pub_key.as_ref().unwrap(), &new_pub_key);
    }
}

// Test procedure, store and vault
// Generate a public from a secret in vault and returns it
fn test_full_stronghold_access(
    stronghold: Stronghold,
    snapshot_path: SnapshotPath,
    client_path: Vec<u8>,
    vault_path: Vec<u8>,
    record_path: Vec<u8>,
    key_provider: KeyProvider,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = stronghold.get_client(client_path.clone()).unwrap();
    let output_location = crate::Location::generic(vault_path.clone(), record_path);

    // Generate key and store it at output_location
    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location.clone(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

    assert!(procedure_result.is_ok());

    let vault_exists = client.vault_exists(vault_path);
    assert!(vault_exists.is_ok());
    assert!(vault_exists.unwrap());

    // Derive the public key of the key previously generated
    let public_key_procedure = PublicKey {
        ty: KeyType::Ed25519,
        private_key: output_location,
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // write client into snapshot
    stronghold.write_client(client_path)?;

    // commit all to snapshot file
    stronghold.commit_with_keyprovider(&snapshot_path, &key_provider)?;

    Ok(output)
}

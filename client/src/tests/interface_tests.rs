// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::BorrowMut,
    error::Error,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};

use crate::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    Client, ClientError, ClientVault, KeyProvider, Location, Snapshot, SnapshotPath, Store, Stronghold,
};
use engine::vault::RecordHint;
use regex::Replacer;
use stronghold_utils::random as rand;
use zeroize::{Zeroize, Zeroizing};

/// Returns a fixed sized vector of random bytes
fn fixed_random_bytes(length: usize) -> Vec<u8> {
    std::iter::repeat_with(rand::random::<u8>).take(length).collect()
}

struct Defer<T, F>
where
    F: FnMut(&T),
{
    cmd: F,
    inner: T,
}

impl<T, F> Drop for Defer<T, F>
where
    F: FnMut(&T),
{
    fn drop(&mut self) {
        (self.cmd)(&mut self.inner)
    }
}

impl<T, F> Deref for Defer<T, F>
where
    F: FnMut(&T),
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, F> DerefMut for Defer<T, F>
where
    F: FnMut(&T),
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, F> From<(T, F)> for Defer<T, F>
where
    F: FnMut(&T),
{
    fn from((inner, cmd): (T, F)) -> Self {
        Self { cmd, inner }
    }
}

#[tokio::test]
async fn test_full_stronghold_access() -> Result<(), Box<dyn Error>> {
    let vault_path = b"vault_path".to_vec();
    let client_path = b"client_path".to_vec();

    // load the base type
    let stronghold = Stronghold::default();

    let key = b"abcdefghijklmnopqrstuvwxyz123456".to_vec();
    let keyprovider = KeyProvider::try_from(Zeroizing::new(key)).map_err(|e| format!("error {:?}", e))?;
    let snapshot_path: SnapshotPath = SnapshotPath::named("testing-snapshot.snapshot");

    let snapshot = Snapshot::default();

    // create a new empty client
    let client = stronghold.create_client(client_path.clone())?;

    let output_location = crate::Location::generic(b"vault_path".to_vec(), b"record_path".to_vec());

    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location.clone(),
        // hint: RecordHint::new(b"").unwrap(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

    assert!(procedure_result.is_ok());

    let vault_exists = client.vault_exists(b"vault_path");
    assert!(vault_exists.is_ok());
    assert!(vault_exists.unwrap());

    // get the public key
    let public_key_procedure = crate::procedures::PublicKey {
        ty: KeyType::Ed25519,
        private_key: output_location,
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure.clone()));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // some store data
    let store = client.store();

    let vault_location = Location::const_generic(vault_path.to_vec(), b"".to_vec());
    let vault = client.vault(b"vault_path");

    // create a new secret inside the vault
    assert!(vault
        .write_secret(
            Location::const_generic(vault_path, b"record-path".to_vec()),
            vec![].into(),
        )
        .is_ok());

    // write client into snapshot
    stronghold.write_client(client_path.clone())?;

    // commit all to snapshot file
    stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider)?;

    //// -- reset stronghold, re-load snapshot from disk

    // reset stronghold
    let stronghold = stronghold.reset();

    println!("load client from snapshot file");
    let client = stronghold.load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)?;

    // Write the state of the client back into the snapshot
    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    assert!(procedure_result.is_ok());

    Ok(())
}

// Tests that a freshly created client and a loaded client are correctly purged.
#[test]
fn test_stronghold_purge_client() {
    let client_path = b"client_path".to_vec();
    let client_path2 = b"client_path2".to_vec();

    let stronghold = Stronghold::default();

    let client = stronghold.create_client(&client_path).unwrap();
    let client2 = stronghold.create_client(&client_path2).unwrap();

    let output_location = crate::Location::generic(b"vault_path".to_vec(), b"record_path".to_vec());

    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location.clone(),
    };

    client.execute_procedure(generate_key_procedure.clone()).unwrap();
    client2.execute_procedure(generate_key_procedure).unwrap();

    // Write clients into snapshot
    stronghold.write_client(&client_path).unwrap();
    stronghold.write_client(&client_path2).unwrap();

    assert!(client.record_exists(&output_location).unwrap());
    assert!(client2.record_exists(&output_location).unwrap());
    assert!(stronghold.unload_client(client2).is_ok());

    let client2 = stronghold.load_client(&client_path2).unwrap();

    stronghold.purge_client(client).unwrap();
    stronghold.purge_client(client2).unwrap();

    // Both clients should no longer be present in the snapshot.
    let err = stronghold.load_client(&client_path).unwrap_err();
    let err2 = stronghold.load_client(&client_path2).unwrap_err();

    assert!(matches!(err, ClientError::ClientDataNotPresent));
    assert!(matches!(err2, ClientError::ClientDataNotPresent));
}

#[test]
fn purge_client() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    // This test will create a client, write secret data into the vault, commit
    // the state into a snapshot. Then purge the client, commit the purged state
    // and reload the client, with an empty state
    let client_path = fixed_random_bytes(1024);
    let vault_path = fixed_random_bytes(1024);
    let record_path = fixed_random_bytes(1024);

    let filename = base64::encode(fixed_random_bytes(8));
    let filename = filename.replace('/', "n");
    let mut snapshot_path = std::env::temp_dir();
    snapshot_path.push(filename);

    let snapshot = SnapshotPath::from_path(&snapshot_path);

    let stronghold = Stronghold::default();

    let result = stronghold.create_client(client_path.clone());
    assert!(result.is_ok());

    let client = result.unwrap();
    let vault = client.vault(vault_path.clone());

    let loc_secret = Location::const_generic(vault_path.clone(), record_path.clone());
    let result = vault.write_secret(loc_secret, fixed_random_bytes(1024).into());

    assert!(result.is_ok());

    let result = KeyProvider::try_from(Zeroizing::new(fixed_random_bytes(32)));
    assert!(result.is_ok());

    let key_provider = result.unwrap();

    let result = stronghold.commit_with_keyprovider(&snapshot, &key_provider);
    assert!(result.is_ok(), "Commit failed {:?}", result);

    // purge client
    assert!(stronghold.purge_client(client).is_ok());

    // the next commit also deletes it from the snapshot file
    let result = stronghold.commit_with_keyprovider(&snapshot, &key_provider);
    assert!(result.is_ok(), "Commit failed {:?}", result);

    // check, if client still exists
    let result = stronghold.load_client(client_path.clone());
    assert!(result.is_err());

    // re-init stronghold
    let stronghold = Stronghold::default();

    // reload from snapshot
    let result = stronghold.load_client_from_snapshot(client_path, &key_provider, &snapshot);
    assert!(result.is_ok(), "Failed to load client from snapshot");

    let client = result.unwrap();
    let vault = client.vault(vault_path);
    assert!(vault.read_secret(record_path).is_err());
}

#[test]
fn write_client_to_snapshot() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let stronghold = Stronghold::default();

    let snapshot_path = {
        let name = base64::encode(fixed_random_bytes(8));
        let name = name.replace('/', "n");

        let mut dir = std::env::temp_dir();
        dir.push(name);

        SnapshotPath::from_path(dir)
    };

    let keyprovider = {
        let key = fixed_random_bytes(32);
        KeyProvider::try_from(Zeroizing::new(key)).expect("Failed to create keyprovider")
    };

    // create a client and write some secret into the state
    {
        let client = stronghold.create_client(fixed_random_bytes(256)).unwrap();
        let vault_path = fixed_random_bytes(256);
        let record_path = fixed_random_bytes(256);
        let vault = client.vault(vault_path.clone());

        vault
            .write_secret(
                Location::const_generic(vault_path, record_path),
                fixed_random_bytes(1024).into(),
            )
            .expect("Failed to write secret into vault");
    }

    let result = stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider);

    assert!(
        result.is_ok(),
        "Failed to commit client data {:?}, snapshot path: {:?}",
        result,
        snapshot_path.as_path()
    );
}

#[test]
fn test_load_client_from_snapshot() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let client_path = fixed_random_bytes(1024);
    let vault_path = fixed_random_bytes(1024);
    let record_path = fixed_random_bytes(1024);

    let filename = base64::encode(fixed_random_bytes(32));
    let filename = filename.replace('/', "n");
    let mut snapshot_path = std::env::temp_dir();
    snapshot_path.push(filename);

    let defer = Defer::from((snapshot_path, |path: &'_ PathBuf| {
        println!("Removing file");
        let _ = std::fs::remove_file(path);
    }));

    let snapshot = SnapshotPath::from_path(&*defer);
    let stronghold = Stronghold::default();

    let result = stronghold.create_client(client_path.clone());
    assert!(result.is_ok());

    let client = result.unwrap();
    let vault = client.vault(vault_path.clone());

    let result = vault.write_secret(
        Location::const_generic(vault_path, record_path),
        fixed_random_bytes(1024).into(),
    );

    assert!(result.is_ok());

    let result = KeyProvider::try_from(Zeroizing::new(fixed_random_bytes(32)));
    assert!(result.is_ok());

    let key_provider = result.unwrap();

    let result = stronghold.commit_with_keyprovider(&snapshot, &key_provider);
    assert!(result.is_ok(), "Commit failed {:?}", result);

    assert!(stronghold.unload_client(client).is_ok());

    // reload from snapshot
    assert!(stronghold
        .load_client_from_snapshot(client_path, &key_provider, &snapshot)
        .is_ok());
}

#[test]
fn test_load_multiple_clients_from_snapshot() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let number_of_clients = 10;
    let client_path_vec: Vec<Vec<u8>> = (0..number_of_clients).map(|_| fixed_random_bytes(256)).collect();
    let mut clients = vec![];

    let stronghold = Stronghold::default();

    let snapshot_path = {
        let name = base64::encode(fixed_random_bytes(8));
        let name = name.replace('/', "n");
        let mut dir = std::env::temp_dir();
        dir.push(name);

        SnapshotPath::from_path(dir)
    };

    let keyprovider = {
        let key = fixed_random_bytes(32);
        KeyProvider::try_from(Zeroizing::new(key)).expect("Failed to create keyprovider")
    };

    client_path_vec.iter().for_each(|path| {
        let client = stronghold.create_client(path.clone()).unwrap();
        clients.push(client);
    });

    let result = stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider);
    assert!(result.is_ok(), "Failed to commit clients state {:?}", result);

    for client in clients.into_iter() {
        assert!(stronghold.unload_client(client).is_ok());
    }

    client_path_vec.iter().for_each(|path| {
        let result = stronghold.load_client_from_snapshot(path, &keyprovider, &snapshot_path);
        assert!(result.is_ok(), "Failed to load client from snapshot path {:?}", result);
    });
}

#[test]
fn test_load_client_from_non_existing_snapshot() {
    let client_path = "my-awesome-client-path";
    let stronghold = Stronghold::default();
    let snapshot_path = SnapshotPath::named(base64::encode(fixed_random_bytes(8)));
    let password = rand::fixed_bytestring(32);
    let keyprovider = KeyProvider::try_from(Zeroizing::new(password)).expect("KeyProvider failed");

    let result = match stronghold.load_client_from_snapshot(client_path, &keyprovider, &snapshot_path) {
        Err(client_error) => {
            std::mem::discriminant(&client_error)
                == std::mem::discriminant(&ClientError::SnapshotFileMissing("obo".to_string()))
        }
        Ok(_) => false,
    };

    assert!(result)
}

#[test]
fn test_create_snapshot_file_in_custom_directory() {
    let client_path = "my-awesome-client-path";
    let vault_path = b"vault_path".to_vec();
    let record_path = b"record_path".to_vec();
    let payload: Zeroizing<Vec<u8>> = b"payload".to_vec().into();
    let location = Location::const_generic(vault_path.clone(), record_path.clone());
    let stronghold = Stronghold::default();
    let mut temp_dir = std::env::temp_dir();

    let mut temp_name = base64::encode(fixed_random_bytes(8));
    temp_name.push_str(".snapshot");

    temp_dir = temp_dir.join(temp_name);

    let snapshot_path = SnapshotPath::from_path(temp_dir.as_path());
    let password = rand::fixed_bytestring(32);
    let keyprovider = KeyProvider::try_from(Zeroizing::new(password)).expect("KeyProvider failed");

    let result = stronghold.create_client(client_path);
    assert!(result.is_ok());

    let client = result.unwrap();
    let vault = client.vault(vault_path.clone());

    assert!(vault.write_secret(location, payload.clone()).is_ok());

    assert!(stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider).is_ok());

    assert!(stronghold.unload_client(client).is_ok());

    let client2 = stronghold.load_client_from_snapshot(client_path, &keyprovider, &snapshot_path);
    assert!(client2.is_ok(), "Failed to load client from snapshot ({:?})", client2);

    let client2 = client2.unwrap();

    let vault2 = client2.vault(vault_path);
    let secret = vault2.read_secret(record_path);
    assert!(secret.is_ok());

    let secret = secret.unwrap();
    assert!(secret.eq(&payload));
}

#[test]
fn test_clear_stronghold_state() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    // pre-requisites
    let client_path = "my-awesome-client-path";
    let vault_path = b"vault_path".to_vec();
    let record_path = b"record_path".to_vec();
    let payload = b"payload".to_vec();
    let location = Location::const_generic(vault_path.clone(), record_path);

    let store_key = rand::fixed_bytestring(32);
    let store_data = rand::fixed_bytestring(1024);

    let mut temp_name = base64::encode(fixed_random_bytes(8));
    temp_name.push_str(".snapshot");

    let mut temp_dir = std::env::temp_dir();

    temp_dir = temp_dir.join(temp_name);
    let defer = Defer::from((temp_dir, |path: &'_ PathBuf| {
        println!("Delete temporary snapshot file");
        let _ = std::fs::remove_file(path);
    }));

    let snapshot_path = SnapshotPath::from_path(defer.as_path());
    let password = rand::fixed_bytestring(32);
    let keyprovider = KeyProvider::try_from(Zeroizing::new(password)).expect("KeyProvider failed");

    // init stronghold
    let stronghold = Stronghold::default();

    let result = stronghold.create_client(client_path);
    assert!(result.is_ok(), "Could not load client {:?}", result);

    let client = result.unwrap();
    let client_store = client.store();
    assert!(client_store.insert(store_key.clone(), store_data, None).is_ok());

    // generate a key
    assert!(client
        .execute_procedure(crate::procedures::GenerateKey {
            output: location.clone(),
            ty: KeyType::Ed25519
        })
        .is_ok());

    // and export its public part
    let result = client.execute_procedure(crate::procedures::PublicKey {
        private_key: location,
        ty: KeyType::Ed25519,
    });

    // assert the public key export succeeded
    assert!(result.is_ok());

    // store the state
    assert!(stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider).is_ok());

    // --
    // clear internal state
    // --
    assert!(stronghold.clear().is_ok());

    // check that vault does not exist. This is actually an odd case, but the reference
    // to client is still present, but the inner state is not  since it is managed by stronghold.
    // it would be safer to drop this reference
    let result = client.vault_exists(vault_path);
    assert!(result.is_ok());

    // check for `false`
    assert!(!result.unwrap());

    let result = client_store.contains_key(&store_key);
    assert!(result.is_ok());

    // check for `false`
    assert!(!result.unwrap());

    // check, that loading a non-exisiting client should fail
    let result = stronghold.load_client(client_path);
    assert!(result.is_err());

    assert!(matches!(result, Err(ClientError::ClientDataNotPresent)));
}

#[test]
fn test_keyprovider_hashed_passphrase() {
    use crypto::hashes::Digest;
    use std::ops::Deref;
    let passphrase = b"passphrase".to_vec();
    let mut blake2b = crypto::hashes::blake2b::Blake2b256::new();
    blake2b.update(&passphrase);
    let expected = blake2b.finalize();
    let result = KeyProvider::with_passphrase_hashed(passphrase, crypto::hashes::blake2b::Blake2b256::new());

    assert!(result.is_ok(), "Failed: {:?}", result);

    let keyprovider = result.unwrap();
    let buffer = keyprovider.try_unlock();

    assert!(buffer.is_ok(), "unlocking the inner buffer failed {:?}", buffer);

    let buffer = buffer.unwrap();
    let buffer_ref = buffer.borrow();
    let key = buffer_ref.deref();

    assert_eq!(key, &expected.to_vec());
}

#[test]
fn test_keyprovider_hashed_passphrase_blake2b() {
    use crypto::hashes::Digest;
    use std::ops::Deref;
    let passphrase = b"passphrase".to_vec();
    let mut blake2b = crypto::hashes::blake2b::Blake2b256::new();
    blake2b.update(&passphrase);
    let expected = blake2b.finalize();
    let result = KeyProvider::with_passphrase_hashed_blake2b(passphrase);

    assert!(result.is_ok(), "Failed: {:?}", result);

    let keyprovider = result.unwrap();
    let buffer = keyprovider.try_unlock();

    assert!(buffer.is_ok(), "unlocking the inner buffer failed {:?}", buffer);

    let buffer = buffer.unwrap();
    let buffer_ref = buffer.borrow();
    let key = buffer_ref.deref();

    assert_eq!(key, &expected.to_vec());
}

#[test]
fn test_stronghold_with_key_location_for_snapshot() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let client_path = "my-awesome-client-path";
    let vault_path = b"vault_path".to_vec();
    let record_path = b"record_path".to_vec();
    let payload = b"payload".to_vec().into();
    let secret_location = Location::const_generic(vault_path.clone(), record_path);
    let key = rand::fixed_bytestring(32);
    let key_provider =
        KeyProvider::with_passphrase_hashed_blake2b(key.clone()).expect("Failed to construct keyprovider");
    let key_location = Location::const_generic(b"secret-key-location".to_vec(), b"secret-key-location".to_vec());

    let filename = base64::encode(fixed_random_bytes(32));
    let filename = filename.replace('/', "n");
    let mut snapshot_path = std::env::temp_dir();
    snapshot_path.push(filename);

    let defer = Defer::from((snapshot_path.clone(), |path: &'_ PathBuf| {
        let _ = std::fs::remove_file(path);
    }));

    let stronghold = Stronghold::default();
    let client = stronghold.create_client(client_path).expect("Failed to create client");
    let vault = client.vault(vault_path);
    let snapshot = SnapshotPath::from_path(&*defer);

    assert!(
        vault.write_secret(secret_location, payload).is_ok(),
        "Failed to write secret to specified location"
    );

    assert!(
        stronghold
            .store_snapshot_key_at_location(key_provider, key_location)
            .is_ok(),
        "Failed to store key at location for Snapshot"
    );

    let result = stronghold.commit(&snapshot);
    assert!(
        result.is_ok(),
        "Failed to commmit all clients state with using implicit key location. ({:?})",
        result
    );

    // reset stronghold
    let stronghold = stronghold.reset();
    let key_provider = KeyProvider::with_passphrase_hashed_blake2b(key).expect("Failed to construct keyprovider");

    let client2 =
        stronghold.load_client_from_snapshot(client_path, &key_provider, &SnapshotPath::from_path(snapshot_path));

    assert!(client2.is_ok());
}

#[test]
fn test_load_unload_client() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let stronghold = Stronghold::default();
    let client_path = "my-awesome-client-path";
    let client = stronghold.create_client(client_path).expect("Failed to create client");

    assert!(stronghold.load_client(client_path).is_err());

    let result = KeyProvider::try_from(Zeroizing::new(fixed_random_bytes(32)));
    assert!(result.is_ok());
    let key_provider = result.unwrap();

    let filename = base64::encode(fixed_random_bytes(32));
    let filename = filename.replace('/', "n");
    let mut snapshot_path = std::env::temp_dir();
    snapshot_path.push(filename);

    let defer = Defer::from((snapshot_path.clone(), |path: &'_ PathBuf| {
        let _ = std::fs::remove_file(path);
    }));
    let snapshot = SnapshotPath::from_path(&*defer);

    let result = stronghold.commit_with_keyprovider(&snapshot, &key_provider);
    assert!(result.is_ok(), "Commit failed {:?}", result);

    assert!(stronghold
        .load_client_from_snapshot(client_path, &key_provider, &snapshot)
        .is_err());

    assert!(stronghold.unload_client(client).is_ok());
    assert!(stronghold.load_client(client_path).is_ok());
}

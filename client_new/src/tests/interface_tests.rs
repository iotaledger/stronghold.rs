// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::BorrowMut, error::Error, path::Path};

use crate::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    Client, ClientVault, KeyProvider, Location, Store, Stronghold,
};
use engine::vault::RecordHint;
use stronghold_utils::random as rand;
use zeroize::Zeroize;

/// This is a testing stub and MUST be removed, if the actual implementation
/// is present
struct Snapshot {}

impl Snapshot {
    pub fn named(filename: String) -> Self {
        todo!()
    }

    pub fn try_from<P>(path: P) -> Result<Self, Box<dyn Error>>
    where
        P: AsRef<Path>,
    {
        todo!()
    }

    pub async fn write(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

/// Returns a fixed sized vector of random bytes
fn fixed_random_bytes(length: usize) -> Vec<u8> {
    std::iter::repeat_with(rand::random::<u8>).take(length).collect()
}

#[tokio::test]
async fn test_full_stronghold_access() -> Result<(), Box<dyn Error>> {
    let vault_path = b"vault_path".to_vec();
    let client_path = b"client_path".to_vec();

    // load the base type
    let stronghold = Stronghold::default();

    let key = fixed_random_bytes(32);
    let keyprovider = KeyProvider::try_from(key).map_err(|e| format!("Error {:?}", e))?;
    let snapshot_path = "/path/to/snapshot";

    // let snapshot = Snapshot::try_from("/path/to/snapshot")?;

    // no mutability allowed!
    let client = Client::default();

    let output_location = crate::Location::generic(b"vault_path".to_vec(), b"record_path".to_vec());

    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location.clone(),
        hint: RecordHint::new(b"").unwrap(),
    };

    let procedure_result = client
        .execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure))
        .await;

    assert!(procedure_result.is_ok());

    let vault_exists = client.vault_exists(b"vault_path".to_vec()).await;
    assert!(vault_exists.is_ok());
    assert!(vault_exists.unwrap());

    let store = client.store().await;

    let vault = client.vault(Location::const_generic(vault_path.to_vec(), b"".to_vec()));

    // create a new secret inside the vault
    assert!(vault
        .write_secret(
            Location::const_generic(vault_path.clone(), b"record-path".to_vec()),
            vec![],
        )
        .is_ok());

    // Write the state of the client back into the snapshot
    // client.update(&snapshot).await?;

    // Write the current state into the snapshot
    // snapshot.write().await?;

    Ok(())
}

#[tokio::test]
async fn test_load_client_from_snapshot() {}

#[tokio::test]
async fn test_load_multiple_clients_from_snapshot() {}

#[tokio::test]
async fn test_multiple_clients_modifikation_from_and_to_snapshot() {}

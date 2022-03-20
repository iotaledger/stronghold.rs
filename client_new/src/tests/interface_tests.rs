// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::BorrowMut, error::Error, path::Path};

use crate::{
    procedures::{GenerateKey, KeyType, StrongholdProcedure},
    Client, ClientVault, KeyProvider, Location, Snapshot, SnapshotPath, Store, Stronghold,
};
use engine::vault::RecordHint;
use stronghold_utils::random as rand;
use zeroize::Zeroize;

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

    let key = b"abcdefghijklmnopqrstuvwxyz123456".to_vec();
    let keyprovider = KeyProvider::try_from(key).map_err(|e| format!("Error {:?}", e))?;
    let snapshot_path: SnapshotPath = SnapshotPath::named("testing-snapshot.snapshot");

    let snapshot = Snapshot::default();

    // create a new empty client
    let client = stronghold.create_client(client_path.clone()).await?;

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

    // get the public key
    let public_key_procedure = crate::procedures::PublicKey {
        ty: KeyType::Ed25519,
        private_key: output_location,
    };

    let procedure_result = client
        .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure.clone()))
        .await;

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // some store data
    let store = client.store().await;

    let vault = client.vault(Location::const_generic(vault_path.to_vec(), b"".to_vec()));

    // create a new secret inside the vault
    assert!(vault
        .write_secret(
            Location::const_generic(vault_path.clone(), b"record-path".to_vec()),
            vec![],
        )
        .is_ok());

    // write client into snapshot
    stronghold.write_client(client_path.clone()).await?;

    // commit all to snapshot file
    stronghold.commit(&snapshot_path, &keyprovider).await?;

    //// -- reset stronghold, re-load snapshot from disk

    // reset stronghold
    let stronghold = stronghold.reset();

    println!("load client from snapshot file");
    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .await?;

    // Write the state of the client back into the snapshot
    let procedure_result = client
        .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
        .await;

    assert!(procedure_result.is_ok());

    Ok(())
}

#[tokio::test]
async fn write_client_to_snapshot() {}

#[tokio::test]
async fn test_load_client_from_snapshot() {}

#[tokio::test]
async fn test_load_multiple_clients_from_snapshot() {}

#[tokio::test]
async fn test_multiple_clients_modifikation_from_and_to_snapshot() {}

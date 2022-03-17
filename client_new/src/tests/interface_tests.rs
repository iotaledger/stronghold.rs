// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, path::Path};

use crate::{Client, KeyProvider, Store, Stronghold, Vault};
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

#[tokio::test]
async fn test_full_stronghold_access() -> Result<(), Box<dyn Error>> {
    let vault_path = b"vault_path".to_vec();
    let client_path = b"client_path".to_vec();

    let keyprovider = KeyProvider::try_from(b"secret".to_vec()).map_err(|e| format!("Error {:?}", e))?;
    let snapshot_path = "/path/to/snapshot";

    let stronghold = Stronghold::default();
    let snapshot = Snapshot::try_from("/path/to/snapshot")?;

    let client = Client::default();

    let store = client.store().await;

    let vault: Vault = client.vault(&vault_path).await;

    // create a new secret inside the vault
    vault.write_secret(vec![], vec![], vec![]).await;

    // Write the state of the client back into the snapshot
    client.update(&snapshot).await?;

    // Write the current state into the snapshot
    snapshot.write().await?;

    Ok(())
}

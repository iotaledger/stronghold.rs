// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, path::Path};

use crate::{Cache, Client, Store, Stronghold, Vault};

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
}

#[tokio::test]
async fn test_full_stronghold_access() -> Result<(), Box<dyn Error>> {
    let vault_path = b"vault_path";
    let client_path = b"client_path";

    let stronghold = Stronghold::default();

    let snapshot = Snapshot::try_from("/path/to/snapshot")?;

    let client = Client::default();

    Ok(())
}

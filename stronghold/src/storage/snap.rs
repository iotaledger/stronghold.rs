// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

pub use engine::snapshot::snapshot_dir;
use engine::snapshot::{decrypt_snapshot, encrypt_snapshot};

use std::{
    fs::{create_dir_all, OpenOptions},
    path::PathBuf,
};

use super::{
    client::{Client, Snapshot},
    provider::Provider,
};
use anyhow::{Context, Result};

// deserialize the snapshot data from the snapshot file.
pub(in crate) fn deserialize_from_snapshot(snapshot: &PathBuf, pass: &str) -> Result<Client<Provider>> {
    let mut buffer = Vec::new();

    let mut file = OpenOptions::new()
        .read(true)
        .open(snapshot)
        .context("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.")?;

    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes()).context("unable to decrypt the snapshot")?;

    let snap: Snapshot<Provider> = bincode::deserialize(&buffer[..]).context("Unable to deserialize data")?;

    let key = snap.offload();
    Ok(Client::<Provider>::new(key))
}

// serialize the snapshot data into the snapshot file.
pub(in crate) fn serialize_to_snapshot(snapshot: &PathBuf, pass: &str, client: Client<Provider>) {
    if let Some(parent) = snapshot.parent() {
        create_dir_all(parent).expect("failed to create snapshot folder");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(snapshot)
        .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");

    // clear contents of the file before writing.
    file.set_len(0).expect("unable to clear the contents of the file file");

    let snap: Snapshot<Provider> = Snapshot::new(client.db.key);

    let data: Vec<u8> = bincode::serialize(&snap).expect("Couldn't serialize the client data");
    encrypt_snapshot(data, &mut file, pass.as_bytes()).expect("Couldn't write to the snapshot");
}

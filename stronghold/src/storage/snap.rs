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

use engine::snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir};

use std::{fs::OpenOptions, path::PathBuf};

use crate::storage::{
    client::{Client, Snapshot},
    provider::Provider,
};

pub fn get_snapshot_path() -> PathBuf {
    let path = snapshot_dir().expect("Unable to get the snapshot path");

    path.join("backup.snapshot")
}

pub fn deserialize_from_snapshot(snapshot: &PathBuf, pass: &str) -> Client<Provider> {
    let mut buffer = Vec::new();

    let mut file = OpenOptions::new()
        .read(true)
        .open(snapshot)
        .expect("Unable to access the snapshot. Make sure it exists.");

    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes());

    let snapshot: Snapshot<Provider> = bincode::deserialize(&buffer[..]).expect("Unable to deserialize data");

    Client::<Provider>::new_from_snapshot(snapshot)
}

pub fn serialize_to_snapshot(snapshot: &PathBuf, pass: &str, mut client: Client<Provider>) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(snapshot)
        .expect("Unable to access snapshot. Make sure that it exists.");

    file.set_len(0).expect("unable to clear the contents of the file file");

    let snap: Snapshot<Provider> = Snapshot::new(&mut client);

    let data: Vec<u8> = bincode::serialize(&snap).expect("Couldn't serialize the client data");
    encrypt_snapshot(data, &mut file, pass.as_bytes()).expect("Couldn't write to the snapshot");
}

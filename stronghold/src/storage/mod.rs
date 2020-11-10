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

/// create a line error with the file and the line number
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

mod bucket;
mod cache;
mod client;
mod provider;
mod snap;

use bucket::Blob;
use client::Client;
use provider::Provider;
use snap::{deserialize_from_snapshot, serialize_to_snapshot, snapshot_dir};

use engine::vault;

pub use vault::{Base64Decodable, Id, Key, RecordHint};

use std::path::{Path, PathBuf};

pub struct Storage {
    snapshot_path: PathBuf,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            snapshot_path: snapshot_dir()
                .expect("failed to get snapshot dir")
                .join("backup.snapshot"),
        }
    }
}

impl Storage {
    /// Creates a new instance of the storage
    pub fn new<P: AsRef<Path>>(snapshot_path: P) -> Self {
        Self {
            snapshot_path: snapshot_path.as_ref().to_path_buf(),
        }
    }

    // handle the encryption command.
    pub fn exists(&self) -> bool {
        self.snapshot_path.exists()
    }

    pub fn encrypt(&self, hint: &str, plain: &str, pass: &str, key: Option<Key<Provider>>) -> (Id, Key<Provider>) {
        let key = if let Some(k) = key {
            k
        } else {
            Key::<Provider>::random().expect("Unable to generate a new key")
        };

        let record_id = if self.exists() {
            let client: Client<Provider> = deserialize_from_snapshot(&self.snapshot_path, pass);

            let tx_id = client.create_record(key, plain.as_bytes().to_vec(), hint.as_bytes());

            serialize_to_snapshot(&self.snapshot_path, pass, client);

            tx_id
        } else {
            let key = Key::<Provider>::random().expect("Unable to generate a new key");
            let id = Id::random::<Provider>().expect("Unable to generate a new id");
            let bucket = Blob::new();

            let client = Client::new(id, bucket);

            let tx_id = client.create_record(key, plain.as_bytes().to_vec(), hint.as_bytes());

            serialize_to_snapshot(&self.snapshot_path, pass, client);

            tx_id
        };

        (record_id.expect("No transaction was created"), key)
    }

    // handle the snapshot command.
    pub fn snapshot(&self, path: &str, pass: &str) {
        let path = Path::new(path);

        let client: Client<Provider> = deserialize_from_snapshot(&path.to_path_buf(), pass);

        let new_path = path.parent().unwrap().join("recomputed.snapshot");
        serialize_to_snapshot(&new_path, pass, client);
    }

    // handle the list command.
    pub fn get_index(&self, pass: &str, key: Key<Provider>) -> Vec<(Id, RecordHint)> {
        let client: Client<Provider> = deserialize_from_snapshot(&self.snapshot_path, pass);

        let index = client.get_index();

        serialize_to_snapshot(&self.snapshot_path, pass, client);

        index
    }

    // handle the read command.
    pub fn read(&self, id: Id, pass: &str, key: Key<Provider>) -> String {
        let client: Client<Provider> = deserialize_from_snapshot(&self.snapshot_path, pass);

        let record = client.read_record_by_id(id);

        serialize_to_snapshot(&self.snapshot_path, pass, client);

        record
    }

    // create a record with a revoke transaction.  Data isn't actually deleted until it is garbage collected.
    pub fn revoke(&self, id: Id, pass: &str, key: Key<Provider>) {
        let client: Client<Provider> = deserialize_from_snapshot(&self.snapshot_path, pass);

        client.revoke_record_by_id(id);

        serialize_to_snapshot(&self.snapshot_path, pass, client);
    }

    // garbage collect the chain.  Remove any revoked data from the chain.
    pub fn garbage_collect_vault(&self, pass: &str, key: Key<Provider>) {
        let client: Client<Provider> = deserialize_from_snapshot(&self.snapshot_path, pass);

        client.perform_gc();
        client.get_index();

        serialize_to_snapshot(&self.snapshot_path, pass, client);
    }
}

#[cfg(test)]
mod tests {
    use super::Storage;

    #[test]
    fn encrypt_value() {
        crate::test_utils::with_snapshot(|path| {
            let storage = Storage::new(path);
            let value = "value_to_encrypt";
            let id = storage.encrypt("", value, "password");

            let read = storage.read(id, "password");
            assert_eq!(read, value);
        });
    }
}

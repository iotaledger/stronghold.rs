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

use engine::vault::{BoxProvider, Id, Key};

use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use crate::storage::bucket::{Blob, Bucket};

pub struct Client<P: BoxProvider + Clone + Send + Sync + 'static> {
    id: Id,
    blobs: Blob<P>,
    _provider: PhantomData<P>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
    pub id: Id,
    pub keys: HashSet<Key<P>>,
    pub state: HashMap<Vec<u8>, Vec<u8>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Client<P> {
    pub fn new(id: Id, blobs: Blob<P>) -> Self {
        Self {
            id,
            blobs,
            _provider: PhantomData,
        }
    }

    pub fn new_from_snapshot(snapshot: Snapshot<P>) -> Self {
        let id = snapshot.id;
        let blobs = Blob::new_from_snapshot(snapshot);

        Self {
            id,
            blobs: blobs,
            _provider: PhantomData,
        }
    }

    pub fn add_vault(&mut self, key: &Key<P>) {
        self.blobs.add_vault(key, self.id);
    }

    pub fn create_record(&mut self, key: Key<P>, payload: Vec<u8>, hint: &[u8]) -> Option<Id> {
        self.blobs.create_record(self.id, key, payload, hint)
    }

    pub fn read_record(&mut self, key: Key<P>, id: Id) {
        self.blobs.read_record(id, key);
    }

    pub fn preform_gc(&mut self, key: Key<P>) {
        self.blobs.garbage_collect(self.id, key)
    }

    pub fn revoke_record_by_id(&mut self, id: Id, key: Key<P>) {
        self.blobs.revoke_record(self.id, id, key)
    }

    pub fn list_valid_ids_for_vault(&mut self, key: Key<P>) {
        self.blobs.list_all_valid_by_key(key)
    }
}

impl<P: BoxProvider + Clone + Send + Sync> Snapshot<P> {
    pub fn new(client: &mut Client<P>) -> Self {
        let id = client.id;
        let (vkeys, state) = client.blobs.clone().offload_data();

        let mut keys = HashSet::new();
        vkeys.iter().for_each(|k| {
            keys.insert(k.clone());
        });

        Self { id, keys, state }
    }

    pub fn offload(self) -> (Id, HashSet<Key<P>>, HashMap<Vec<u8>, Vec<u8>>) {
        (self.id, self.keys, self.state)
    }
}

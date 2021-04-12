// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalResults, SHRequest, SHResults},
    line_error,
    utils::LoadFromPath,
    Location,
};

use engine::{
    store::Cache,
    vault::{ClientId, RecordId, VaultId},
};

use riker::actors::*;

use std::{collections::HashSet, time::Duration};

use serde::{Deserialize, Serialize};

type Store = Cache<Vec<u8>, Vec<u8>>;

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.
#[actor(SHResults, SHRequest, InternalResults)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashSet<VaultId>,
    // Contains the Record Ids for the most recent Record in each vault.
    store: Store,
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let vaults = HashSet::new();

        let store = Cache::new();

        Self {
            client_id,
            vaults,
            store,
        }
    }

    /// Write unencrypted data to the store.  Returns `None` if the key didn't already exist and `Some(Vec<u8>)` if the
    /// key was updated.
    pub fn write_to_store(&mut self, key: Vec<u8>, data: Vec<u8>, lifetime: Option<Duration>) -> Option<Vec<u8>> {
        self.store.insert(key, data, lifetime)
    }

    /// Attempts to read the data from the store.  Returns `Some(Vec<u8>)` if the key exists and `None` if it doesn't.
    pub fn read_from_store(&mut self, key: Vec<u8>) -> Option<Vec<u8>> {
        let res = self.store.get(&key);

        if let Some(vec) = res {
            Some(vec.to_vec())
        } else {
            None
        }
    }

    /// Deletes an item from the store by the given key.
    pub fn store_delete_item(&mut self, key: Vec<u8>) {
        self.store.remove(&key);
    }

    /// Checks to see if the key exists in the store.
    pub fn store_key_exists(&mut self, key: Vec<u8>) -> bool {
        self.store.contains_key(&key)
    }

    pub fn set_client_id(&mut self, client_id: ClientId) {
        self.client_id = client_id
    }

    pub fn add_new_vault(&mut self, vid: VaultId) {
        self.vaults.insert(vid);
    }

    /// Get the head of a vault.

    /// Empty the Client Cache.
    pub fn clear_cache(&mut self) -> Option<()> {
        self.vaults = HashSet::default();

        Some(())
    }

    pub fn rebuild_cache(&mut self, state: Client) {
        *self = Self {
            client_id: self.client_id,
            ..state
        }
    }

    pub fn resolve_location<L: AsRef<Location>>(&self, l: L) -> (VaultId, RecordId) {
        match l.as_ref() {
            Location::Generic {
                vault_path,
                record_path,
            } => {
                let vid = self.derive_vault_id(vault_path);
                let rid = RecordId::load_from_path(vid.as_ref(), record_path).expect(line_error!(""));
                (vid, rid)
            }
            Location::Counter { vault_path, counter } => {
                let vid = self.derive_vault_id(vault_path);

                let rid = self.derive_record_id(vault_path, *counter);

                (vid, rid)
            }
        }
    }

    pub fn derive_vault_id<P: AsRef<Vec<u8>>>(&self, path: P) -> VaultId {
        VaultId::load_from_path(path.as_ref(), path.as_ref()).expect(line_error!(""))
    }

    pub fn derive_record_id<P: AsRef<Vec<u8>>>(&self, vault_path: P, ctr: usize) -> RecordId {
        let vault_path = vault_path.as_ref();

        let path = if ctr == 0 {
            format!("{:?}{}", vault_path, "first_record")
        } else {
            format!("{:?}{}", vault_path, ctr)
        };

        RecordId::load_from_path(path.as_bytes(), path.as_bytes()).expect(line_error!())
    }

    pub fn get_client_str(&self) -> String {
        self.client_id.into()
    }

    pub fn vault_exist(&self, vid: VaultId) -> Option<&VaultId> {
        self.vaults.get(&vid)
    }

    pub fn get_index_from_record_id<P: AsRef<Vec<u8>>>(&self, vault_path: P, record_id: RecordId) -> usize {
        let mut ctr = 0;
        let vault_path = vault_path.as_ref();
        let vault_id = self.derive_vault_id(vault_path);

        while ctr <= 32_000_000 {
            let rid = self.derive_record_id(vault_path, ctr);
            if record_id == rid {
                break;
            }
            ctr += 1;
        }

        ctr
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::Provider;

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_new_vault(vid);

        assert_eq!(cache.vaults.get(&vid), Some(&vid));
    }

    #[test]
    fn test_rid_internals() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let vault_path = b"some_vault".to_vec();

        let mut client = Client::new(clientid);
        let mut ctr = 0;
        let mut ctr2 = 0;

        let rid = client.derive_record_id(vault_path.clone(), ctr);
        let rid2 = client.derive_record_id(vault_path.clone(), ctr2);

        client.add_new_vault(vid);

        client.add_new_vault(vid2);

        ctr += 1;
        ctr2 += 1;

        let rid = client.derive_record_id(vault_path.clone(), ctr);
        let rid2 = client.derive_record_id(vault_path.clone(), ctr2);

        ctr += 1;

        let rid = client.derive_record_id(vault_path.clone(), ctr);

        let test_rid = client.derive_record_id(vault_path, 2);

        assert_eq!(test_rid, rid);
    }

    #[test]
    fn test_location_counter_api() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vidlochead = Location::counter::<_, usize>("some_vault", 0);
        let vidlochead2 = Location::counter::<_, usize>("some_vault 2", 0);

        let mut client = Client::new(clientid);

        let (vid, rid) = client.resolve_location(vidlochead.clone());
        let (vid2, rid2) = client.resolve_location(vidlochead2.clone());

        client.add_new_vault(vid);

        client.add_new_vault(vid2);

        let (_, rid_head) = client.resolve_location(vidlochead.clone());
        let (_, rid_head_2) = client.resolve_location(vidlochead2.clone());

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);

        let (vid, rid) = client.resolve_location(vidlochead.clone());
        let (vid2, rid2) = client.resolve_location(vidlochead2.clone());

        let (_, rid_head) = client.resolve_location(vidlochead);
        let (_, rid_head_2) = client.resolve_location(vidlochead2);

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);
    }
}

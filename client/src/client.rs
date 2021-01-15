// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalResults, SHRequest, SHResults},
    line_error,
    utils::LoadFromPath,
    ClientId, Location, VaultId,
};

use engine::{store::Cache, vault::RecordId};
#[cfg(feature = "communication")]
use stronghold_communication::actor::CommunicationEvent;

use riker::actors::*;

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

type Store = Cache<Vec<u8>, Vec<u8>>;

pub enum ReadWrite {
    Read,
    Write,
}

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.

#[cfg(not(feature = "communication"))]
#[actor(SHResults, SHRequest, InternalResults)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    counters: Vec<usize>,
    store: Store,
}

#[cfg(feature = "communication")]
#[actor(SHResults, SHRequest, InternalResults, CommunicationEvent<SHRequest, SHResults>)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    counters: Vec<usize>,
    store: Store,
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let vaults = HashMap::new();
        let heads = vec![];

        let counters = vec![0];
        let store = Cache::new();

        Self {
            client_id,
            vaults,
            heads,
            counters,
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
        let head = self.heads.len();

        self.vaults.insert(vid, (head, vec![]));
    }

    pub fn add_record_to_vault(&mut self, vid: VaultId, rid: RecordId) {
        let mut heads = self.heads.clone();

        let (idx, _) = self
            .vaults
            .entry(vid)
            .and_modify(|(_, rids)| {
                rids.push(rid);
            })
            .or_insert((heads.len(), vec![rid]));

        if heads.len() <= *idx {
            heads.push(rid);
        } else {
            heads[*idx] = rid;
        }

        if self.counters.len() == *idx {
            self.counters.push(0);
        }

        self.heads = heads;
    }

    pub fn increment_counter(&mut self, vid: VaultId) {
        let opt = self.vaults.get(&vid);

        if let Some((idx, _)) = opt {
            if self.counters.len() == *idx {
                self.counters.push(0);
            }

            self.counters[*idx] += 1;
        }
    }

    /// Get the head of a vault.
    pub fn get_head(&self, vault_path: Vec<u8>) -> RecordId {
        let vid = self.derive_vault_id(vault_path.clone());
        let idx = self.get_index(vid);

        if let Some(idx) = idx {
            self.heads[idx]
        } else {
            let ctr = self.get_counter(vid);
            let path = if ctr == 0 {
                format!("{:?}{}", vault_path, "first_record")
            } else {
                format!("{:?}{}", vault_path, ctr)
            };

            RecordId::load_from_path(path.as_bytes(), path.as_bytes()).expect(line_error!())
        }
    }

    /// Empty the Client Cache.
    pub fn clear_cache(&mut self) -> Option<()> {
        self.heads = vec![];
        self.vaults = HashMap::default();
        self.counters = vec![0];

        Some(())
    }

    pub fn rebuild_cache(&mut self, state: Client) {
        *self = Self {
            client_id: self.client_id,
            ..state
        }
    }

    pub fn resolve_location<L: AsRef<Location>>(&self, l: L, rw: ReadWrite) -> (VaultId, RecordId) {
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

                let rid = if let Some(ctr) = counter {
                    self.derive_record_id(vault_path, *ctr)
                } else {
                    let ctr = self.get_counter(vid);
                    match rw {
                        ReadWrite::Read => self.derive_record_id(vault_path, ctr - 1),
                        ReadWrite::Write => self.derive_record_id(vault_path, ctr),
                    }
                };

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

    pub fn record_exists_in_vault(&self, vid: VaultId, rid: RecordId) -> bool {
        let opts = self.vaults.get(&vid);
        if let Some((_, rids)) = opts {
            rids.iter().any(|r| r == &rid)
        } else {
            false
        }
    }

    pub fn vault_exist(&self, vid: VaultId) -> bool {
        self.vaults.contains_key(&vid)
    }

    pub fn get_index_from_record_id<P: AsRef<Vec<u8>>>(&self, vault_path: P, record_id: RecordId) -> usize {
        let mut ctr = 0;
        let vault_path = vault_path.as_ref();
        let vault_id = self.derive_vault_id(vault_path);

        let vctr = self.get_counter(vault_id);

        while ctr <= vctr {
            let rid = self.derive_record_id(vault_path, ctr);
            if record_id == rid {
                break;
            }
            ctr += 1;
        }

        ctr
    }

    fn get_index(&self, vid: VaultId) -> Option<usize> {
        let idx = self.vaults.get(&vid);

        if let Some((idx, _)) = idx {
            Some(*idx)
        } else {
            None
        }
    }

    pub fn get_counter(&self, vid: VaultId) -> usize {
        match self.get_index(vid) {
            Some(idx) => self.counters[idx],
            None => 0,
        }
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
        cache.add_record_to_vault(vid, rid);
        cache.increment_counter(vid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        cache.add_record_to_vault(vid, rid);
        cache.increment_counter(vid);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(1usize, vec![rid])));
    }

    #[test]
    fn test_insert() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_new_vault(vid);
        cache.add_record_to_vault(vid, rid);
        cache.increment_counter(vid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_record_to_vault(vid, rid2);
        cache.increment_counter(vid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid2);

        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_new_vault(vid2);
        cache.add_record_to_vault(vid2, rid3);
        cache.increment_counter(vid2);
        cache.add_record_to_vault(vid2, rid4);
        cache.increment_counter(vid2);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid4);

        assert_eq!(cache.vaults.get(&vid2), Some(&(1usize, vec![rid3, rid4])));
    }

    #[test]
    fn test_get_head_and_vault() {
        let cid = ClientId::random::<Provider>().expect(line_error!());

        let vault_path = b"some_vault".to_vec();
        let vault_path2 = b"some_vault2".to_vec();

        let vid = VaultId::load_from_path(&vault_path, &vault_path).expect(line_error!(""));
        let vid2 = VaultId::load_from_path(&vault_path2, &vault_path2).expect(line_error!(""));

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(cid);

        cache.add_new_vault(vid);
        cache.add_record_to_vault(vid, rid);
        cache.add_new_vault(vid2);
        cache.add_record_to_vault(vid2, rid3);

        cache.increment_counter(vid);
        cache.increment_counter(vid2);

        cache.add_record_to_vault(vid, rid2);
        cache.add_record_to_vault(vid2, rid4);

        cache.increment_counter(vid);
        cache.increment_counter(vid2);

        let head0 = cache.get_head(vault_path);
        let head1 = cache.get_head(vault_path2);

        assert_eq!(head0, rid2);
        assert_eq!(head1, rid4);
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
        client.add_record_to_vault(vid, rid);
        client.add_new_vault(vid2);
        client.add_record_to_vault(vid2, rid2);
        client.increment_counter(vid);
        client.increment_counter(vid2);

        ctr += 1;
        ctr2 += 1;

        let rid = client.derive_record_id(vault_path.clone(), ctr);
        let rid2 = client.derive_record_id(vault_path.clone(), ctr2);

        client.add_record_to_vault(vid, rid);
        client.add_record_to_vault(vid2, rid2);
        client.increment_counter(vid);
        client.increment_counter(vid2);

        ctr += 1;

        let rid = client.derive_record_id(vault_path.clone(), ctr);

        client.add_record_to_vault(vid, rid);
        client.increment_counter(vid);

        let test_ctr = client.get_counter(vid);
        let test_rid = client.derive_record_id(vault_path, test_ctr - 1);

        assert_eq!(test_rid, rid);
        assert_eq!(Some(test_ctr), Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }

    #[test]
    fn test_location_counter_api() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vidlochead = Location::counter::<_, usize>("some_vault", None);
        let vidlochead2 = Location::counter::<_, usize>("some_vault 2", None);

        let mut client = Client::new(clientid);

        let (vid, rid) = client.resolve_location(vidlochead.clone(), ReadWrite::Write);
        let (vid2, rid2) = client.resolve_location(vidlochead2.clone(), ReadWrite::Write);

        client.add_new_vault(vid);
        client.add_record_to_vault(vid, rid);
        client.add_new_vault(vid2);
        client.add_record_to_vault(vid2, rid2);
        client.increment_counter(vid);
        client.increment_counter(vid2);

        let (_, rid_head) = client.resolve_location(vidlochead.clone(), ReadWrite::Read);
        let (_, rid_head_2) = client.resolve_location(vidlochead2.clone(), ReadWrite::Read);

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);

        let (vid, rid) = client.resolve_location(vidlochead.clone(), ReadWrite::Write);
        let (vid2, rid2) = client.resolve_location(vidlochead2.clone(), ReadWrite::Write);

        client.add_record_to_vault(vid, rid);
        client.add_record_to_vault(vid2, rid2);
        client.increment_counter(vid);
        client.increment_counter(vid2);

        let (_, rid_head) = client.resolve_location(vidlochead, ReadWrite::Read);
        let (_, rid_head_2) = client.resolve_location(vidlochead2, ReadWrite::Read);

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);
    }
}

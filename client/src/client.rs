// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalResults, SHRequest, SHResults},
    line_error,
    utils::LoadFromPath,
    ClientId, VaultId,
};

use engine::vault::RecordId;

use riker::actors::*;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum Location {
    Generic {
        vault_path: Vec<u8>,
        record_path: Vec<u8>,
    },
    Counter {
        vault_path: Vec<u8>,
        counter: Option<usize>,
    },
}

impl Location {
    pub fn vault_path(&self) -> &[u8] {
        match self {
            Self::Generic { vault_path, .. } => vault_path,
            Self::Counter { vault_path, .. } => vault_path,
        }
    }

    pub fn generic<V: Into<Vec<u8>>, R: Into<Vec<u8>>>(vault_path: V, record_path: R) -> Self {
        Self::Generic {
            vault_path: vault_path.into(),
            record_path: record_path.into(),
        }
    }

    pub fn counter<V: Into<Vec<u8>>, C: Into<usize>>(vault_path: V, counter: Option<C>) -> Self {
        Self::Counter {
            vault_path: vault_path.into(),
            counter: counter.map(|c| c.into()),
        }
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.
#[actor(SHResults, SHRequest, InternalResults)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: BTreeMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    counters: Vec<usize>,
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let vaults = BTreeMap::new();
        let heads = Vec::new();
        let counters = vec![0];

        Self {
            client_id,
            vaults,
            heads,
            counters,
        }
    }

    pub fn offload_client(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    /// Insert a new Record into the Stronghold on the Vault based on the given RecordId.
    pub fn add_vault_insert_record(&mut self, vid: VaultId, rid: RecordId) -> (VaultId, RecordId) {
        let mut heads: Vec<RecordId> = self.heads.clone();

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

        if !heads.contains(&rid) {
            heads.push(rid);
        }

        if self.counters.len() == *idx {
            self.counters.push(0);
        }

        self.counters[*idx] += 1;

        self.heads = heads;

        (vid, rid)
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
        self.vaults = BTreeMap::default();
        self.counters = vec![0];

        Some(())
    }

    pub fn rebuild_cache(&mut self, state: Vec<u8>) {
        let client: Client = bincode::deserialize(&state).expect(line_error!());

        *self = client;
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
        VaultId::load_from_path(self.client_id.as_ref(), path.as_ref()).expect(line_error!(""))
    }

    pub fn derive_record_id<P: AsRef<Vec<u8>>>(&self, vault_path: P, ctr: Option<usize>) -> RecordId {
        let vault_path = vault_path.as_ref();
        let vid = self.derive_vault_id(vault_path);
        if let Some(ctr) = ctr {
            let path = if ctr == 0 {
                format!("{:?}{}", vault_path, "first_record")
            } else {
                format!("{:?}{}", vault_path, ctr)
            };

            RecordId::load_from_path(path.as_bytes(), path.as_bytes()).expect(line_error!())
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
            let rid = self.derive_record_id(vault_path, Some(ctr));
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

        cache.add_vault_insert_record(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault_insert_record(vid, rid);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(1usize, vec![rid])));
    }

    #[test]
    fn test_insert() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_vault_insert_record(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault_insert_record(vid, rid2);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid2);

        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault_insert_record(vid2, rid3);
        cache.add_vault_insert_record(vid2, rid4);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid4);

        assert_eq!(cache.vaults.get(&vid2), Some(&(1usize, vec![rid3, rid4])));
    }

    #[test]
    fn test_get_head_and_vault() {
        let cid = ClientId::random::<Provider>().expect(line_error!());
        let data: Vec<u8> = cid.into();
        let vault_path = b"some_vault".to_vec();
        let vault_path2 = b"some_vault2".to_vec();

        let vid = VaultId::load_from_path(&data, &vault_path).expect(line_error!(""));
        let vid2 = VaultId::load_from_path(&data, &vault_path2).expect(line_error!(""));

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(cid);

        cache.add_vault_insert_record(vid, rid);
        cache.add_vault_insert_record(vid, rid2);
        cache.add_vault_insert_record(vid2, rid3);
        cache.add_vault_insert_record(vid2, rid4);

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

        let rid = client.derive_record_id(vault_path.clone(), Some(ctr));
        let rid2 = client.derive_record_id(vault_path.clone(), Some(ctr2));

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        ctr += 1;
        ctr2 += 1;

        let rid = client.derive_record_id(vault_path.clone(), Some(ctr));
        let rid2 = client.derive_record_id(vault_path.clone(), Some(ctr2));

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        ctr += 1;

        let rid = client.derive_record_id(vault_path.clone(), Some(ctr));

        client.add_vault_insert_record(vid, rid);

        let test_ctr = client.get_counter(vid);
        let test_rid = client.derive_record_id(vault_path, Some(test_ctr - 1));

        assert_eq!(test_rid, rid);
        assert_eq!(Some(test_ctr), Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }

    #[test]
    fn test_rid_derive() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let vault_path = b"some_vault".to_vec();

        let mut client = Client::new(clientid);

        let rid = client.derive_record_id(vault_path.clone(), None);
        let rid2 = client.derive_record_id(vault_path.clone(), None);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        let rid = client.derive_record_id(vault_path.clone(), None);
        let rid2 = client.derive_record_id(vault_path.clone(), None);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        let rid = client.derive_record_id(vault_path.clone(), None);

        client.add_vault_insert_record(vid, rid);

        let test_ctr = client.get_counter(vid);
        let test_rid = client.derive_record_id(vault_path, None);

        assert!(client.record_exists_in_vault(vid, test_rid));
        assert!(client.vault_exist(vid));

        assert_eq!(test_rid, rid);
        assert_eq!(Some(test_ctr), Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }
}

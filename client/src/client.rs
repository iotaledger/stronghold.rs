// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalResults, SHRequest, SHResults},
    line_error,
    utils::{LoadFromPath, StatusMessage},
    ClientId, VaultId,
};

use engine::vault::RecordId;

use riker::actors::*;

use std::{collections::HashMap, path::PathBuf};

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.
#[actor(SHResults, SHRequest, InternalResults)]
#[derive(Debug)]
pub struct Client {
    client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    counters: Vec<usize>,
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();
        let counters = Vec::new();

        Self {
            client_id,
            vaults,
            heads,
            counters,
        }
    }

    /// Add a vault to the client.  Returns a Tuple of `VaultId` and `RecordId`.
    pub fn add_vault(&mut self, vid: VaultId, rid: RecordId) -> (VaultId, RecordId) {
        self.heads.push(rid);
        self.counters.push(1);

        let idx = self.heads.len();

        let idx = idx - 1;

        self.vaults.insert(vid, (idx, vec![rid]));

        (vid, rid)
    }

    /// Insert a new Record into the Stronghold on the Vault based on the given RecordId.
    pub fn insert_record(&mut self, vid: VaultId, rid: RecordId) -> RecordId {
        let mut heads: Vec<RecordId> = self.heads.clone();

        let (idx, _) = self
            .vaults
            .entry(vid)
            .and_modify(|(_, rids)| {
                rids.push(rid);
            })
            .or_insert((0, vec![rid]));

        if heads.len() <= *idx {
            heads.push(rid);
        } else {
            heads[*idx] = rid;
        }

        if !heads.contains(&rid) {
            heads.push(rid);
        }

        self.heads = heads;
        self.increment_counter(vid);
        rid
    }

    /// Get the head of a vault.
    pub fn get_head(&mut self, vid: VaultId) -> RecordId {
        let idx = self.get_index(vid);

        if let Some(idx) = idx {
            self.heads[idx]
        } else {
            self.derive_record_id(vid, None)
        }
    }

    /// Empty the Client Cache.
    pub fn clear_cache(&mut self) -> Option<()> {
        self.heads = vec![];
        self.vaults = HashMap::default();

        Some(())
    }

    pub fn rebuild_cache(&mut self, vids: Vec<VaultId>, rids: Vec<Vec<RecordId>>) {
        let iter = vids.iter().zip(rids.iter());

        for (v, rs) in iter {
            rs.iter().for_each(|r| {
                self.insert_record(*v, *r);
            });
        }
    }

    pub fn derive_vault_id(&self, path: Vec<u8>) -> VaultId {
        let data: Vec<u8> = self.client_id.into();

        VaultId::load_from_path(&data, &path).expect(line_error!(""))
    }

    pub fn derive_record_id(&mut self, vault_id: VaultId, ctr: Option<usize>) -> RecordId {
        let data: Vec<u8> = self.client_id.into();
        let vid_str: String = vault_id.into();
        let vcntr = self.get_counter(vault_id);

        if let Some(vcntr) = vcntr {
            if let Some(cnt) = ctr {
                let path_counter = format!("{}{}", vid_str, cnt);

                RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
            } else {
                let path_counter = format!("{}{}", vid_str, vcntr - 1);

                RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
            }
        } else {
            let path_counter = format!("{}{}", vid_str, 0);

            RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
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

    pub fn get_record_index(&self, vid: VaultId) -> usize {
        let opt = self.get_counter(vid);

        if let Some(ctr) = opt {
            ctr
        } else {
            0
        }
    }

    fn get_index(&self, vid: VaultId) -> Option<usize> {
        let idx = self.vaults.get(&vid);

        if let Some((idx, _)) = idx {
            Some(*idx)
        } else {
            None
        }
    }

    fn get_counter(&self, vid: VaultId) -> Option<usize> {
        let idx = self.get_index(vid);

        if let Some(idx) = idx {
            Some(self.counters[idx])
        } else {
            None
        }
    }

    fn increment_counter(&mut self, vid: VaultId) {
        let idx = self.get_index(vid);

        if let Some(idx) = idx {
            self.counters[idx] += 1
        }
    }
}

/// Actor Factor for the Client Struct.

#[cfg(test)]
mod test {
    use super::*;

    use crate::Provider;

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_vault(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid, rid);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(1usize, vec![rid])));
    }

    #[test]
    fn test_insert() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.insert_record(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        cache.insert_record(vid, rid2);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid2);

        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid2, rid3);
        cache.insert_record(vid2, rid4);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid4);

        assert_eq!(cache.vaults.get(&vid2), Some(&(1usize, vec![rid3, rid4])));
    }

    #[test]
    fn test_get_head_and_vault() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_vault(vid, rid);
        cache.insert_record(vid, rid2);
        cache.add_vault(vid2, rid3);
        cache.insert_record(vid2, rid4);

        let head0 = cache.get_head(vid);
        let head1 = cache.get_head(vid2);

        assert_eq!(head0, rid2);
        assert_eq!(head1, rid4);
    }

    #[test]
    fn test_vault_id() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let mut client = Client::new(clientid);
        let ctr = client.get_counter(vid);

        let rid = client.derive_record_id(vid, ctr);
        let rid2 = client.derive_record_id(vid2, ctr);

        client.add_vault(vid, rid);
        client.add_vault(vid2, rid2);
        let ctr = client.get_counter(vid);
        let rid = client.derive_record_id(vid, ctr);
        let rid2 = client.derive_record_id(vid2, ctr);

        client.insert_record(vid, rid);
        client.insert_record(vid2, rid2);
        let ctr = client.get_counter(vid);

        let rid = client.derive_record_id(vid, ctr);

        client.insert_record(vid, rid);

        let test_rid = client.derive_record_id(vid, Some(2));
        let test_ctr = client.get_counter(vid);

        println!("{}", client.derive_record_id(vid, None));
        println!("{}", test_rid);
        println!("{:?}", client);

        assert_eq!(test_rid, rid);
        assert_eq!(test_ctr, Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }
}

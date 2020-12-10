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

use std::collections::HashMap;

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
        let counters = vec![0];

        Self {
            client_id,
            vaults,
            heads,
            counters,
        }
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

        if self.counters.len() <= *idx {
            self.counters.push(0);
        }

        self.counters[*idx] += 1;

        self.heads = heads;

        (vid, rid)
    }

    /// Get the head of a vault.
    pub fn get_head(&self, vid: VaultId) -> RecordId {
        let idx = self.get_index(vid);

        if let Some(idx) = idx {
            self.heads[idx]
        } else {
            self.derive_record_id_next(vid)
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
            let mut counter = 0;
            rs.iter().for_each(|r| {
                self.add_vault_insert_record(*v, *r);
                counter += 1;
            });
            self.counters.push(counter);
        }
    }

    pub fn derive_vault_id(&self, path: Vec<u8>) -> VaultId {
        let data: Vec<u8> = self.client_id.into();

        VaultId::load_from_path(&data, &path).expect(line_error!(""))
    }

    pub fn derive_record_id(&self, vault_id: VaultId, ctr: Option<usize>) -> RecordId {
        if let Some(ctr) = ctr {
            self.derive_record_id_from_ctr(vault_id, ctr)
        } else {
            self.derive_record_id_next(vault_id)
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

    pub fn get_counter_index(&self, vid: VaultId) -> usize {
        let opt = self.get_counter(vid);

        if let Some(ctr) = opt {
            ctr
        } else {
            0
        }
    }

    fn derive_record_id_from_ctr(&self, vault_id: VaultId, ctr: usize) -> RecordId {
        let data: Vec<u8> = self.client_id.into();
        let vid_str: String = vault_id.into();
        let vctr = self.get_counter_index(vault_id);

        if ctr > vctr {
            let path_counter = format!("{}{}", vid_str, vctr - 1);
            RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
        } else {
            let path_counter = format!("{}{}", vid_str, ctr);

            RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
        }
    }

    fn derive_record_id_next(&self, vault_id: VaultId) -> RecordId {
        let data: Vec<u8> = self.client_id.into();
        let vid_str: String = vault_id.into();
        let vctr = self.get_counter_index(vault_id);

        let path_counter = format!("{}{}", vid_str, vctr);

        RecordId::load_from_path(&data, &path_counter.as_bytes()).expect(line_error!(""))
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
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()));

        cache.add_vault_insert_record(vid, rid);
        cache.add_vault_insert_record(vid, rid2);
        cache.add_vault_insert_record(vid2, rid3);
        cache.add_vault_insert_record(vid2, rid4);

        let head0 = cache.get_head(vid);
        let head1 = cache.get_head(vid2);

        assert_eq!(head0, rid2);
        assert_eq!(head1, rid4);
    }

    #[test]
    fn test_rid_internals() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let mut client = Client::new(clientid);
        let mut ctr = 0;
        let mut ctr2 = 0;

        let rid = client.derive_record_id_from_ctr(vid, ctr);
        let rid2 = client.derive_record_id_from_ctr(vid2, ctr2);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        ctr += 1;
        ctr2 += 1;

        let rid = client.derive_record_id_from_ctr(vid, ctr);
        let rid2 = client.derive_record_id_from_ctr(vid2, ctr2);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        ctr += 1;

        let rid = client.derive_record_id_from_ctr(vid, ctr);

        client.add_vault_insert_record(vid, rid);

        let test_ctr = client.get_counter_index(vid);
        let test_rid = client.derive_record_id(vid, Some(test_ctr));

        assert_eq!(test_rid, rid);
        assert_eq!(Some(test_ctr), Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }

    #[test]
    fn test_rid_derive() {
        let clientid = ClientId::random::<Provider>().expect(line_error!());

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let mut client = Client::new(clientid);

        let rid = client.derive_record_id(vid, None);
        let rid2 = client.derive_record_id(vid2, None);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        let rid = client.derive_record_id(vid, None);
        let rid2 = client.derive_record_id(vid2, None);

        client.add_vault_insert_record(vid, rid);
        client.add_vault_insert_record(vid2, rid2);

        let rid = client.derive_record_id(vid, None);

        client.add_vault_insert_record(vid, rid);

        let test_ctr = client.get_counter_index(vid);
        let test_rid = client.derive_record_id(vid, Some(test_ctr - 1));

        assert!(client.record_exists_in_vault(vid, test_rid));
        assert!(client.vault_exist(vid));

        assert_eq!(test_rid, rid);
        assert_eq!(Some(test_ctr), Some(3));
        assert_eq!(client.counters, vec![3, 2])
    }
}

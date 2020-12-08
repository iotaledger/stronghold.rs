// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{SHRequest, SHResults},
    line_error,
    utils::StatusMessage,
    {ClientId, VaultId},
};

use engine::vault::{RecordHint, RecordId};

use riker::actors::*;

use std::{collections::HashMap, path::PathBuf};

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.
#[actor(SHRequest, SHResults)]
pub struct Client {
    client_id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();

        Self {
            client_id,
            vaults,
            heads,
        }
    }

    /// Add a vault to the client.  Returns a Tuple of `VaultId` and `RecordId`.
    pub fn add_vault(&mut self, vid: VaultId, rid: RecordId) -> (VaultId, RecordId) {
        self.heads.push(rid);

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

        rid
    }

    /// Get the head of a vault.
    pub fn get_head(&self, vid: VaultId) -> RecordId {
        let (idx, _) = self.vaults.get(&vid).expect(line_error!("Vault doesn't exist"));

        self.heads[*idx]
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

        VaultId::load(&data).expect(line_error!(""))
    }

    pub fn derive_record_id(&self, path: Vec<u8>) -> RecordId {
        let data: Vec<u8> = self.client_id.into();

        RecordId::load(&data).expect(line_error!(""))
    }
}

// /// Actor Factor for the Client Struct.

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
}

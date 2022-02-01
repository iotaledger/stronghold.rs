// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Client Actor State

use crate::{
    actors::{RecordError, VaultError},
    internals,
    procedures::{FatalProcedureError, Products, Runner},
    state::key_store::KeyStore,
    utils::LoadFromPath,
    Location,
};
use engine::{
    runtime::GuardedVec,
    store::Cache,
    vault::{BlobId, ClientId, DbView, RecordHint, RecordId, VaultId},
};
use std::{collections::HashMap, time::Duration};

/// Cache type definition
pub type Store = Cache<Vec<u8>, Vec<u8>>;

pub struct SecureClient {
    // A keystore
    pub(crate) keystore: KeyStore,
    // A view on the vault entries
    pub(crate) db: DbView<internals::Provider>,
    // The id of this client
    pub client_id: ClientId,
    // Contains the Record Ids for the most recent Record in each vault.
    pub store: Store,
}

// Collect for each (source, target)-vault pair the list of records that are copied between these two vaults.
pub struct LocationMap {
    pub map: HashMap<VaultId, HashMap<VaultId, Vec<(RecordId, RecordId)>>>,
}

impl SecureClient {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let store = Cache::new();

        Self {
            client_id,
            store,
            keystore: KeyStore::new(),
            db: DbView::new(),
        }
    }

    /// Write unencrypted data to the store.  Returns [`None`] if the key didn't already exist and [`Some(Vec<u8>)`] if
    /// the key was updated.
    pub fn write_to_store(&mut self, key: Vec<u8>, data: Vec<u8>, lifetime: Option<Duration>) -> Option<Vec<u8>> {
        self.store.insert(key, data, lifetime)
    }

    /// Attempts to read the data from the store.  Returns [`Some(Vec<u8>)`] if the key exists and [`None`] if it
    /// doesn't.
    pub fn read_from_store(&mut self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.store.get(&key).map(|v| v.to_vec())
    }

    /// Deletes an item from the store by the given key.
    pub fn store_delete_item(&mut self, key: Vec<u8>) {
        self.store.remove(&key);
    }

    /// Checks to see if the key exists in the store.
    pub fn store_key_exists(&mut self, key: Vec<u8>) -> bool {
        self.store.contains_key(&key)
    }

    /// Sets the client id to swap from one client to another.
    pub fn set_client_id(&mut self, client_id: ClientId) {
        self.client_id = client_id
    }

    /// Rebuilds the cache using the parameters.
    pub fn rebuild_cache(&mut self, id: ClientId, store: Store) {
        self.client_id = id;
        self.store = store;
    }

    /// Resolves a location to a `VaultId` and a `RecordId`
    pub fn resolve_location<L: AsRef<Location>>(l: L) -> (VaultId, RecordId) {
        match l.as_ref() {
            Location::Generic {
                vault_path,
                record_path,
            } => {
                let vid = Self::derive_vault_id(vault_path);
                let rid = RecordId::load_from_path(vid.as_ref(), record_path);
                (vid, rid)
            }
            Location::Counter { vault_path, counter } => {
                let vid = Self::derive_vault_id(vault_path);
                let rid = Self::derive_record_id(vault_path, *counter);

                (vid, rid)
            }
        }
    }

    /// Gets the [`VaultId`] from a specified path.
    pub fn derive_vault_id<P: AsRef<Vec<u8>>>(path: P) -> VaultId {
        VaultId::load_from_path(path.as_ref(), path.as_ref())
    }

    /// Derives the counter [`RecordId`] from the given vault path and the counter value.
    pub fn derive_record_id<P: AsRef<Vec<u8>>>(vault_path: P, ctr: usize) -> RecordId {
        let vault_path = vault_path.as_ref();

        let path = if ctr == 0 {
            format!("{:?}{}", vault_path, "first_record")
        } else {
            format!("{:?}{}", vault_path, ctr)
        };

        RecordId::load_from_path(path.as_bytes(), path.as_bytes())
    }

    /// Gets the client string.
    pub fn get_client_str(&self) -> String {
        self.client_id.into()
    }

    /// Gets the current index of a record if its a counter.
    pub fn get_index_from_record_id<P: AsRef<Vec<u8>>>(&self, vault_path: P, record_id: RecordId) -> usize {
        let mut ctr = 0;
        let vault_path = vault_path.as_ref();

        while ctr <= 32_000_000 {
            let rid = Self::derive_record_id(vault_path, ctr);
            if record_id == rid {
                break;
            }
            ctr += 1;
        }

        ctr
    }

    /// Collect the full hierarchy of vaults and their records in the client.
    /// For each record, the [`RecordId`] and [`BlobId`] is listed, to allow comparison between two records.
    pub fn get_full_hierarchy(&mut self) -> Result<HashMap<VaultId, Vec<(RecordId, BlobId)>>, VaultError> {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let key = self.keystore.take_key(vid).ok_or(VaultError::VaultNotFound(vid))?;
            let list = self.db.list_records_with_blob_id(&key, vid)?;
            map.insert(vid, list);
        }
        Ok(map)
    }

    /// Compare the local vaults and records with a given map. Returns the entries from the map that does not exists in
    /// the local hierarchy. If a record already exists, the [`BlobId`] is compared. In case of a conflict it follows
    /// the policy set in the `replace_on_conflict` parameter.
    pub fn get_diff(
        &mut self,
        other: HashMap<VaultId, Vec<(RecordId, BlobId)>>,
        replace_on_conflict: bool,
    ) -> Result<HashMap<VaultId, Vec<RecordId>>, RecordError> {
        let mut diff = HashMap::new();
        for (vid, records) in other {
            if !self.keystore.vault_exists(vid) {
                let records = records.into_iter().map(|(rid, _)| rid).collect();
                diff.insert(vid, records);
                continue;
            }

            let key = self.keystore.take_key(vid).unwrap();

            let mut records_diff = Vec::new();
            for (rid, blob_id) in records {
                match self.db.get_blob_id(&key, vid, rid) {
                    Ok(bid) if bid == blob_id => {}
                    Ok(_) if !replace_on_conflict => {}
                    Ok(_)
                    | Err(VaultError::Record(RecordError::RecordNotFound(_)))
                    | Err(VaultError::VaultNotFound(_)) => records_diff.push(rid),
                    Err(VaultError::Record(e)) => return Err(e),
                    Err(VaultError::Procedure(_)) => unreachable!("Infallible."),
                }
            }
            diff.insert(vid, records_diff);
        }
        Ok(diff)
    }

    /// Copy records between two locations.
    /// Note: this replaces the target location if it already exists.
    pub fn copy_records(&mut self, loc_map: LocationMap) -> Result<(), VaultError> {
        // This has complexity O(n), as every rid0 is only present a single time in the hierarchy.
        for (vid0, target_mapping) in loc_map.map {
            let key0 = self.keystore.take_key(vid0).ok_or(VaultError::VaultNotFound(vid0))?;
            for (vid1, map_records) in target_mapping {
                if !self.keystore.vault_exists(vid1) {
                    let key1 = self.keystore.create_key(vid1);
                    self.db.init_vault(key1, vid1);
                }
                let key1 = self.keystore.take_key(vid1).unwrap();
                self.db
                    .copy_records_single_vault(vid0, &key0, vid1, &key1, map_records)?;
            }
        }
        Ok(())
    }
}

impl Runner for SecureClient {
    fn get_guard<F, T>(&mut self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<T, FatalProcedureError>,
    {
        let (vault_id, record_id) = Self::resolve_location(location);
        let key = self
            .keystore
            .take_key(vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        let mut ret = None;
        let execute_procedure = |guard: GuardedVec<u8>| {
            ret = Some(f(guard)?);
            Ok(())
        };
        let res = self.db.get_guard(&key, vault_id, record_id, execute_procedure);
        self.keystore.insert_key(vault_id, key);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn exec_proc<F, T>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<Products<T>, FatalProcedureError>,
    {
        let (vid0, rid0) = Self::resolve_location(location0);
        let (vid1, rid1) = Self::resolve_location(location1);

        let key0 = self.keystore.take_key(vid0).ok_or(VaultError::VaultNotFound(vid0))?;

        let mut ret = None;
        let execute_procedure = |guard: GuardedVec<u8>| {
            let Products { output: plain, secret } = f(guard)?;
            ret = Some(plain);
            Ok(secret)
        };

        let res;
        if vid0 == vid1 {
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key0, vid1, rid1, hint, execute_procedure);
        } else {
            if !self.keystore.vault_exists(vid1) {
                let key1 = self.keystore.create_key(vid1);
                self.db.init_vault(key1, vid1);
            }
            let key1 = self.keystore.take_key(vid1).unwrap();
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key1, vid1, rid1, hint, execute_procedure);
            self.keystore.insert_key(vid1, key1);
        }

        self.keystore.insert_key(vid0, key0);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn write_to_vault(&mut self, location: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), RecordError> {
        let (vault_id, record_id) = Self::resolve_location(location);
        if !self.keystore.vault_exists(vault_id) {
            let key = self.keystore.create_key(vault_id);
            self.db.init_vault(key, vault_id);
        }
        let key = self.keystore.take_key(vault_id).unwrap();
        let res = self.db.write(&key, vault_id, record_id, &value, hint);
        self.keystore.insert_key(vault_id, key);
        res
    }

    fn revoke_data(&mut self, location: &Location) -> Result<(), RecordError> {
        let (vault_id, record_id) = Self::resolve_location(location);
        if let Some(key) = self.keystore.take_key(vault_id) {
            let res = self.db.revoke_record(&key, vault_id, record_id);
            self.keystore.insert_key(vault_id, key);
            res?;
        }
        Ok(())
    }

    fn garbage_collect(&mut self, vault_id: VaultId) -> bool {
        let key = match self.keystore.take_key(vault_id) {
            Some(key) => key,
            None => return false,
        };
        self.db.garbage_collect_vault(&key, vault_id);
        self.keystore.insert_key(vault_id, key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Provider;

    #[test]
    fn test_rid_internals() {
        let clientid = ClientId::random::<Provider>().unwrap();

        let vault_path = b"some_vault".to_vec();

        let client: SecureClient = SecureClient::new(clientid);
        let mut ctr = 0;
        let mut ctr2 = 0;

        let _rid = SecureClient::derive_record_id(vault_path.clone(), ctr);
        let _rid2 = SecureClient::derive_record_id(vault_path.clone(), ctr2);

        ctr += 1;
        ctr2 += 1;

        let _rid = SecureClient::derive_record_id(vault_path.clone(), ctr);
        let _rid2 = SecureClient::derive_record_id(vault_path.clone(), ctr2);

        ctr += 1;

        let rid = SecureClient::derive_record_id(vault_path.clone(), ctr);

        let test_rid = SecureClient::derive_record_id(vault_path.clone(), 2);
        let ctr = client.get_index_from_record_id(vault_path, rid);

        assert_eq!(test_rid, rid);
        assert_eq!(2, ctr);
    }

    #[test]
    fn test_location_counter_api() {
        let vidlochead = Location::counter::<_, usize>("some_vault", 0);
        let vidlochead2 = Location::counter::<_, usize>("some_vault 2", 0);

        let (_, rid) = SecureClient::resolve_location(&vidlochead);
        let (_, rid2) = SecureClient::resolve_location(&vidlochead2);

        let (_, rid_head) = SecureClient::resolve_location(&vidlochead);
        let (_, rid_head_2) = SecureClient::resolve_location(&vidlochead2);

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);
    }
}

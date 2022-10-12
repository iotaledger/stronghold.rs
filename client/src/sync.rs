// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{view::Record, BlobId, ClientId, DbView, Key, RecordId, VaultId};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use crate::{
    derive_record_id, derive_vault_id, Client, ClientError, ClientState, KeyStore, LoadFromPath, Provider, RecordError,
    SnapshotError, SnapshotState, VaultError,
};

/// Policy for conflicts when merging two vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePolicy {
    /// Do not copy the record, instead keep the existing one.
    KeepOld,
    /// Replace the existing record.
    Replace,
}

impl Default for MergePolicy {
    fn default() -> Self {
        MergePolicy::Replace
    }
}

/// Config for synching two clients.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncClientsConfig {
    pub(crate) select_vaults: Option<Vec<VaultId>>,
    pub(crate) select_records: HashMap<VaultId, Vec<RecordId>>,
    pub(crate) map_vaults: HashMap<VaultId, VaultId>,
    pub(crate) merge_policy: MergePolicy,
}

impl SyncClientsConfig {
    /// Create a new [`SyncClientsConfig`].
    /// Set the merge policy for when a record exists both, at source and the target, with different
    /// content.
    pub fn new(merge_policy: MergePolicy) -> Self {
        SyncClientsConfig {
            merge_policy,
            ..Default::default()
        }
    }

    /// Only perform a partial sync with selected vaults.
    ///
    /// Note: This is referring to the paths as they are on the source client, not
    /// to the mapped path.
    pub fn sync_selected_vaults<P: AsRef<[u8]>>(&mut self, vault_paths: Vec<P>) {
        let select_vaults = vault_paths.into_iter().map(derive_vault_id).collect();
        let _ = self.select_vaults.insert(select_vaults);
    }

    /// Perform for a vault only a partial sync so that only the specified records
    /// are copied.
    pub fn sync_selected_record<V, R>(&mut self, vault_path: V, record_paths: Vec<R>)
    where
        V: AsRef<[u8]>,
        R: AsRef<[u8]>,
    {
        let select_records = record_paths
            .into_iter()
            .map(|path| derive_record_id(&vault_path, path))
            .collect();
        let vid = derive_vault_id(vault_path);
        self.select_records.insert(vid, select_records);
    }

    /// Map the `vault_path` from the source to a local `vault_path`.
    /// If no mapping is set for a vault it assumes that the `vault_path` is the same
    /// on source and target.
    pub fn map_vaults<P: AsRef<[u8]>>(&mut self, map_vault_paths: HashMap<P, P>) {
        let map_vaults = map_vault_paths
            .into_iter()
            .map(|(path_a, path_b)| (derive_vault_id(path_a), derive_vault_id(path_b)));
        self.map_vaults.extend(map_vaults)
    }
}

pub(crate) enum KeyProvider<'a> {
    KeyStore(RwLockReadGuard<'a, KeyStore<Provider>>),
    KeyMap(&'a HashMap<VaultId, Key<Provider>>),
}

pub(crate) type ClientHierarchy<T> = HashMap<VaultId, Vec<T>>;

pub(crate) trait SyncClients<'a> {
    type Db: Deref<Target = DbView<Provider>>;

    fn get_db(&'a self) -> Result<Self::Db, ClientError>;
    fn get_key_provider(&'a self) -> Result<KeyProvider<'a>, ClientError>;

    fn get_hierarchy(
        &'a self,
        vaults: Option<Vec<VaultId>>,
    ) -> Result<ClientHierarchy<(RecordId, BlobId)>, ClientError> {
        let key_provider = self.get_key_provider()?;
        let db = self.get_db()?;
        let vaults = vaults.unwrap_or_else(|| db.list_vaults());
        let mut hierarchy = HashMap::new();
        for vid in vaults {
            let list = match &key_provider {
                KeyProvider::KeyStore(ks) => {
                    let key = match ks.get_key(vid) {
                        Some(k) => k,
                        None => continue,
                    };
                    db.list_records_with_blob_id(&key, vid)?
                }
                KeyProvider::KeyMap(map) => {
                    let key = match map.get(&vid) {
                        Some(k) => k,
                        None => continue,
                    };
                    db.list_records_with_blob_id(key, vid)?
                }
            };
            hierarchy.insert(vid, list);
        }
        Ok(hierarchy)
    }

    fn get_diff(
        &'a self,
        other: ClientHierarchy<(RecordId, BlobId)>,
        config: &SyncClientsConfig,
    ) -> Result<ClientHierarchy<RecordId>, ClientError> {
        let key_provider = self.get_key_provider()?;
        let db = self.get_db()?;
        let mut diff = HashMap::new();
        for (vid, list) in other {
            if let Some(select_vaults) = config.select_vaults.as_ref() {
                if !select_vaults.contains(&vid) {
                    continue;
                }
            }
            let mapped_vid = config.map_vaults.get(&vid).copied().unwrap_or(vid);
            if !db.contains_vault(&mapped_vid) {
                let d = list.into_iter().map(|(rid, _)| rid).collect();
                diff.insert(vid, d);
                continue;
            }
            let select_records = config.select_records.get(&vid);
            let mut record_diff = Vec::new();
            for (rid, bid) in list {
                if let Some(select_records) = select_records {
                    if !select_records.contains(&rid) {
                        continue;
                    }
                }
                if !db.contains_record(mapped_vid, rid) {
                    record_diff.push(rid);
                    continue;
                }
                if matches!(config.merge_policy, MergePolicy::KeepOld) {
                    continue;
                }
                match &key_provider {
                    KeyProvider::KeyStore(ks) => {
                        if let Some(target_key) = ks.get_key(vid) {
                            if db.get_blob_id(&target_key, mapped_vid, rid)? == bid {
                                continue;
                            }
                        }
                    }
                    KeyProvider::KeyMap(map) => {
                        if let Some(target_key) = map.get(&vid) {
                            if db.get_blob_id(target_key, mapped_vid, rid)? == bid {
                                continue;
                            }
                        }
                    }
                }
                record_diff.push(rid);
            }
            diff.insert(vid, record_diff);
        }
        Ok(diff)
    }

    fn export_entries(
        &'a self,
        select: ClientHierarchy<RecordId>,
    ) -> Result<ClientHierarchy<(RecordId, Record)>, ClientError> {
        let db = self.get_db()?;
        let mut export = HashMap::new();
        for (vid, select) in select {
            let records = db.export_records(vid, select)?;
            export.insert(vid, records);
        }
        Ok(export)
    }
}

pub(crate) type SnapshotHierarchy<T> = HashMap<ClientId, HashMap<VaultId, Vec<T>>>;

/// Config for synching two snapshots.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncSnapshotsConfig {
    pub(crate) select_clients: Option<Vec<ClientId>>,
    pub(crate) client_config: HashMap<ClientId, SyncClientsConfig>,
    pub(crate) map_clients: HashMap<ClientId, ClientId>,
    pub(crate) merge_policy: MergePolicy,
}

impl SyncSnapshotsConfig {
    /// Create a new [`SyncSnapshotsConfig`].
    /// Set the merge policy for when a record exists both, at source and the target, with different
    /// content.
    pub fn new(merge_policy: MergePolicy) -> Self {
        SyncSnapshotsConfig {
            merge_policy,
            ..Default::default()
        }
    }

    /// Only perform a partial sync with selected clients.
    ///
    /// Note: This is referring to the paths as they are on the source, not
    /// to the mapped id.
    pub fn sync_selected_clients<P: AsRef<[u8]>>(&mut self, client_paths: Vec<P>) {
        let select_clients = client_paths
            .into_iter()
            .map(|path| ClientId::load_from_path(path.as_ref(), path.as_ref()))
            .collect();
        let _ = self.select_clients.insert(select_clients);
    }

    /// Configure the sync for a client.
    ///
    /// Note: This is referring to the client-path as it is on the source, not
    /// to the mapped path.
    pub fn config_client_sync<P: AsRef<[u8]>>(&mut self, client_path: P, config: SyncClientsConfig) {
        let cid = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        self.client_config.insert(cid, config);
    }

    /// Map the `client_path` from the source to a local `client_path`.
    /// If no mapping is set for a client it assumes that the `client_path` is the same
    /// on source and target.
    pub fn map_clients<P: AsRef<[u8]>>(&mut self, map_client_paths: HashMap<P, P>) {
        let map_clients = map_client_paths.into_iter().map(|(path_a, path_b)| {
            let cid_a = ClientId::load_from_path(path_a.as_ref(), path_a.as_ref());
            let cid_b = ClientId::load_from_path(path_b.as_ref(), path_b.as_ref());
            (cid_a, cid_b)
        });
        self.map_clients.extend(map_clients)
    }
}

pub(crate) trait SyncSnapshots {
    fn clients(&self) -> Vec<ClientId>;
    fn get_from_state<F, T>(&self, cid: ClientId, f: F) -> Result<T, SnapshotError>
    where
        F: FnOnce(Option<&ClientState>) -> Result<T, SnapshotError>;
    fn update_state<F>(&mut self, cid: ClientId, f: F) -> Result<(), SnapshotError>
    where
        F: FnOnce(&mut ClientState) -> Result<(), SnapshotError>;

    fn get_hierarchy(
        &self,
        clients: Option<Vec<ClientId>>,
    ) -> Result<SnapshotHierarchy<(RecordId, BlobId)>, SnapshotError> {
        let clients = clients.unwrap_or_else(|| self.clients());
        let mut hierarchy = HashMap::new();
        for cid in clients {
            let f = |state: Option<&ClientState>| -> Result<_, SnapshotError> {
                let state = match state {
                    Some(s) => s,
                    None => return Ok(None),
                };
                let hierarchy = state.get_hierarchy(None)?;
                Ok(Some(hierarchy))
            };
            if let Some(h) = self.get_from_state(cid, f)? {
                hierarchy.insert(cid, h);
            }
        }
        Ok(hierarchy)
    }

    fn get_diff(
        &self,
        other: SnapshotHierarchy<(RecordId, BlobId)>,
        config: &SyncSnapshotsConfig,
    ) -> Result<SnapshotHierarchy<RecordId>, SnapshotError> {
        let mut diff = HashMap::new();
        for (cid, hierarchy) in other {
            if let Some(select_clients) = config.select_clients.as_ref() {
                if !select_clients.contains(&cid) {
                    continue;
                }
            }
            let mapped_cid = config.map_clients.get(&cid).copied().unwrap_or(cid);
            let f = |state: Option<&ClientState>| -> Result<_, SnapshotError> {
                let state = match state {
                    Some(s) => s,
                    None => return Ok(None),
                };
                let client_diff = match config.client_config.get(&cid) {
                    Some(c) => state.get_diff(hierarchy, c)?,
                    None => {
                        let config = SyncClientsConfig {
                            merge_policy: config.merge_policy,
                            ..Default::default()
                        };
                        state.get_diff(hierarchy, &config)?
                    }
                };
                Ok(Some(client_diff))
            };
            if let Some(client_diff) = self.get_from_state(cid, f)? {
                diff.insert(cid, client_diff);
            }
        }
        Ok(diff)
    }

    fn export_entries(
        &self,
        select: SnapshotHierarchy<RecordId>,
    ) -> Result<SnapshotHierarchy<(RecordId, Record)>, SnapshotError> {
        let mut export = HashMap::new();
        for (cid, select) in select {
            let f = |state: Option<&ClientState>| {
                let state = match state {
                    Some(s) => s,
                    None => return Ok(None),
                };
                let entries = state.export_entries(select)?;
                Ok(Some(entries))
            };
            if let Some(entries) = self.get_from_state(cid, f)? {
                export.insert(cid, entries);
            }
        }
        Ok(export)
    }

    fn import_records(
        &mut self,
        records: SnapshotHierarchy<(RecordId, Record)>,
        old_keys: &HashMap<ClientId, HashMap<VaultId, Key<Provider>>>,
        config: &SyncSnapshotsConfig,
    ) -> Result<(), SnapshotError> {
        for (cid, records) in records {
            if let Some(select_clients) = config.select_clients.as_ref() {
                if !select_clients.contains(&cid) {
                    continue;
                }
            }
            let old_keystore = old_keys
                .get(&cid)
                .ok_or_else(|| SnapshotError::Inner(format!("Missing KeyStore for client {:?}", cid)))?;
            let mapped_cid = config.map_clients.get(&cid).copied().unwrap_or(cid);
            let import_records = |state: &mut ClientState, config: &SyncClientsConfig| {
                for (vid, mut records) in records {
                    if let Some(select_vaults) = config.select_vaults.as_ref() {
                        if !select_vaults.contains(&vid) {
                            continue;
                        }
                    }
                    if let Some(select_records) = config.select_records.get(&vid) {
                        records.retain(|(rid, _)| select_records.contains(rid));
                    }
                    let mapped_vid = config.map_vaults.get(&vid).copied().unwrap_or(vid);
                    state.0.entry(vid).or_insert_with(Key::random);
                    let old_key = old_keystore
                        .get(&vid)
                        .ok_or_else(|| SnapshotError::Inner(format!("Missing Key for vault {:?}", vid)))?;
                    let new_key = state.0.get(&mapped_vid).expect("Key was inserted.");
                    state.1.import_records(old_key, new_key, vid, records)?;
                }
                Ok(())
            };
            let f = match config.client_config.get(&cid) {
                Some(c) => self.update_state(cid, |state| import_records(state, c)),
                None => {
                    let config = SyncClientsConfig {
                        merge_policy: config.merge_policy,
                        ..Default::default()
                    };
                    self.update_state(cid, |state| import_records(state, &config))
                }
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use super::*;

    use crate::{derive_record_id, derive_record_id_from_counter, derive_vault_id, procedures::Runner, Location};
    use engine::vault::RecordHint;
    use stronghold_utils::random;

    fn test_hint() -> RecordHint {
        random::random::<[u8; 24]>().into()
    }

    fn test_value() -> Vec<u8> {
        random::variable_bytestring(4096)
    }

    fn test_location() -> Location {
        let v_path = random::variable_bytestring(4096);
        let r_path = random::variable_bytestring(4096);
        Location::generic(v_path, r_path)
    }

    fn vault_path_to_id(path: &str) -> VaultId {
        derive_vault_id(path.as_bytes())
    }

    fn r_ctr_to_id(vault_path: &str, ctr: usize) -> RecordId {
        derive_record_id_from_counter(vault_path.as_bytes(), ctr)
    }

    #[test]
    fn test_get_hierarchy() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::default();
        let hierarchy = client.get_hierarchy(None)?;
        assert!(hierarchy.is_empty());

        let location_1 = test_location();
        let (vid1, rid1) = location_1.resolve();
        client.write_to_vault(&location_1, test_value())?;

        let v_path_2 = random::variable_bytestring(4096);
        let r_path_2 = random::variable_bytestring(4096);
        let location_2 = Location::generic(v_path_2.clone(), r_path_2);
        let (vid2, rid2) = location_2.resolve();
        client.write_to_vault(&location_2, test_value())?;

        // Same vault as value nr 2.
        let r_path_3 = random::variable_bytestring(4096);
        let location_3 = Location::generic(v_path_2, r_path_3);
        let (vid23, rid3) = location_3.resolve();
        assert_eq!(vid2, vid23);
        client.write_to_vault(&location_3, test_value())?;

        let hierarchy = client.get_hierarchy(None)?;

        assert_eq!(hierarchy.len(), 2);
        let records_1 = hierarchy
            .iter()
            .find(|(k, _)| **k == vid1)
            .expect("Vault does not exist.")
            .1;
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0].0, rid1);

        let records_2 = hierarchy
            .iter()
            .find(|(k, _)| **k == vid2)
            .expect("Vault does not exist.")
            .1;
        assert_eq!(records_2.len(), 2);
        assert!(records_2.iter().any(|(rid, _)| rid == &rid2));
        assert!(records_2.iter().any(|(rid, _)| rid == &rid3));

        Ok(())
    }

    #[test]
    fn test_partial_sync_with_mapping() -> Result<(), Box<dyn std::error::Error>> {
        let source = Client::default();

        let merge_policy = match random::random() {
            true => MergePolicy::KeepOld,
            false => MergePolicy::Replace,
        };

        // Partial sync with only selected vaults.
        let mut config = SyncClientsConfig {
            select_vaults: Some(Vec::new()),
            merge_policy,
            ..Default::default()
        };

        let v_path_1 = random::variable_bytestring(1024);
        let vid1 = derive_vault_id(v_path_1.clone());

        let v_path_2 = random::variable_bytestring(1024);
        let vid2 = derive_vault_id(v_path_2);

        // Include vault-1 in the sync.
        config.select_vaults.as_mut().unwrap().push(vid1);
        // Map vault-1 to vault-2:
        config.map_vaults.insert(vid1, vid2);

        for i in 0..3usize {
            let location = Location::counter(v_path_1.clone(), 10 + i);
            source.write_to_vault(&location, test_value())?;
        }

        let v_path_3 = random::variable_bytestring(1024);
        let vid3 = derive_vault_id(v_path_3.clone());
        // Include vault-3 in the sync, but only selected records.
        config.select_vaults.as_mut().unwrap().push(vid3);

        let mut select_records_v3 = Vec::new();

        for i in 0..3usize {
            let location = Location::counter(v_path_3.clone(), 30 + i);
            source.write_to_vault(&location, test_value())?;
            // Only include record-0 and record-1 in the sync.
            if i == 0 || i == 1 {
                select_records_v3.push(location.resolve().1);
            }
        }
        config.select_records.insert(vid3, select_records_v3);

        // Vault-4 is not included in the sync.
        let v_path_4 = random::variable_bytestring(1024);
        let vid4 = derive_vault_id(v_path_4.clone());

        let v_path_5 = random::variable_bytestring(1024);
        let vid5 = derive_vault_id(v_path_5);
        // Irrelevant mapping of vault-4 to vault-5.
        config.map_vaults.insert(vid4, vid5);

        for i in 0..3usize {
            let location = Location::counter(v_path_4.clone(), 40 + i);
            source.write_to_vault(&location, test_value())?;
        }

        let target = Client::default();

        let source_hierarchy_full = source.get_hierarchy(None)?;
        assert_eq!(source_hierarchy_full.keys().len(), 3);

        let source_hierarchy_partial = source.get_hierarchy(config.select_vaults.clone())?;
        assert_eq!(source_hierarchy_partial.keys().len(), 2);

        let target_hierarchy = target.get_hierarchy(None)?;
        assert!(target_hierarchy.is_empty());

        // Do sync.
        target.sync_with(&source, config)?;

        // Check that old state still contains all values
        let check_hierarchy = source.get_hierarchy(None)?;
        assert_eq!(source_hierarchy_full, check_hierarchy);

        let mut target_hierarchy = target.get_hierarchy(None)?;
        // Only two vaults (Vault-1 and Vault-3) were imported.
        assert_eq!(target_hierarchy.keys().len(), 2);

        // Vault-1 does not exists.
        assert!(!target_hierarchy.contains_key(&vid1));

        // All records from Vault-1 were imported to Vault-2.
        let v_2_entries = target_hierarchy.remove(&vid2).expect("Vault does not exist.");
        assert_eq!(v_2_entries.len(), 3);
        assert!(v_2_entries
            .iter()
            .any(|(rid, _)| *rid == Location::counter(v_path_1.clone(), 10usize).resolve().1));
        assert!(v_2_entries
            .iter()
            .any(|(rid, _)| *rid == Location::counter(v_path_1.clone(), 11usize).resolve().1));
        assert!(v_2_entries
            .iter()
            .any(|(rid, _)| *rid == Location::counter(v_path_1.clone(), 12usize).resolve().1));

        // Record-0 and Record-1 were imported from Vault-3
        let v_3_entries = target_hierarchy.remove(&vid3).expect("Vault does not exist.");
        assert_eq!(v_3_entries.len(), 2);
        assert!(v_3_entries
            .iter()
            .any(|(rid, _)| *rid == Location::counter(v_path_3.clone(), 30usize).resolve().1));
        assert!(v_3_entries
            .iter()
            .any(|(rid, _)| *rid == Location::counter(v_path_3.clone(), 31usize).resolve().1));

        Ok(())
    }

    #[test]
    fn test_merge_policy() -> Result<(), Box<dyn std::error::Error>> {
        let source = Client::default();

        // Fill test vaults.
        for i in 1..3usize {
            for j in 1..3usize {
                let vault_path = format!("vault_{}", i);
                let location = Location::counter(vault_path, i * 10 + j);
                source.write_to_vault(&location, test_value())?;
            }
        }

        let mut source_vault_2_hierarchy = source
            .get_hierarchy(None)?
            .remove(&vault_path_to_id("vault_2"))
            .expect("Vault does not exist.");
        source_vault_2_hierarchy.sort();
        let source_v2_r2_bid = source_vault_2_hierarchy
            .iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| *bid)
            .expect("Record does not exist.");

        let set_up_target = || -> Result<Client, VaultError<Infallible>> {
            let target = Client::default();
            for i in 2..4usize {
                for j in 2..4usize {
                    let vault_path = format!("vault_{}", i);
                    let location = Location::counter(vault_path, i * 10 + j);
                    target.write_to_vault(&location, test_value())?;
                }
            }
            Ok(target)
        };

        let assert_for_distinct_vaults = |hierarchy: &mut HashMap<VaultId, Vec<(RecordId, BlobId)>>| {
            // Imported full vault-1;
            assert_eq!(hierarchy.keys().len(), 3);
            let v_1_entries = hierarchy
                .remove(&vault_path_to_id("vault_1"))
                .expect("Vault does not exist.");
            assert_eq!(v_1_entries.len(), 2);
            assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 11)));
            assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 12)));

            // Kept old vault-3;
            let v_3_entries = hierarchy
                .remove(&vault_path_to_id("vault_3"))
                .expect("Vault does not exist.");
            assert_eq!(v_3_entries.len(), 2);
            assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 32)));
            assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 33)));
        };

        // == Test merge policy MergePolicy::KeepOld

        let target_1 = set_up_target()?;
        let old_v2_r2_bid = target_1
            .get_hierarchy(None)?
            .remove(&vault_path_to_id("vault_2"))
            .and_then(|vec| vec.into_iter().find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)))
            .map(|(_, bid)| bid)
            .expect("Record does not exist.");
        let config = SyncClientsConfig {
            merge_policy: MergePolicy::KeepOld,
            ..Default::default()
        };
        target_1.sync_with(&source, config)?;
        let mut hierarchy = target_1.get_hierarchy(None)?;

        assert_for_distinct_vaults(&mut hierarchy);

        // Merge vault-2 with imported one, keep old record on conflict.
        let v_2_entries = hierarchy
            .remove(&vault_path_to_id("vault_2"))
            .expect("Vault does not exist.");
        assert_eq!(v_2_entries.len(), 3);
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
        let v2_r2_bid = v_2_entries
            .into_iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| bid)
            .expect("Record does not exist.");
        assert_eq!(v2_r2_bid, old_v2_r2_bid);

        // == Test merge policy MergePolicy::Replace

        let target_2 = set_up_target()?;
        let config = SyncClientsConfig {
            merge_policy: MergePolicy::Replace,
            ..Default::default()
        };
        target_2.sync_with(&source, config)?;
        let mut hierarchy = target_2.get_hierarchy(None)?;

        assert_for_distinct_vaults(&mut hierarchy);

        // Merge vault-2 with imported one, keep old record on conflict.
        let v_2_entries = hierarchy
            .remove(&vault_path_to_id("vault_2"))
            .expect("Vault does not exist.");
        assert_eq!(v_2_entries.len(), 3);
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
        let v2_r2_bid = v_2_entries
            .into_iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| bid)
            .expect("Record does not exist.");
        assert_eq!(v2_r2_bid, source_v2_r2_bid);

        Ok(())
    }
}

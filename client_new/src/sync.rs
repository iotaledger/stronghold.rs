// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{view::Record, BlobId, ClientId, DbView, Key, RecordId, VaultId};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use crate::{Client, ClientError, ClientState, KeyStore, Provider, RecordError, SnapshotState, VaultError};

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

// TODO: Use *_paths instead of `Ids`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncClientsConfig {
    /// Optionally only perform a partial sync with specific vaults.
    /// In case of `None` all vaults are synched.
    ///
    /// Note: This is referring to the Ids as they are on the source client, not
    /// to the mapped id.
    pub select_vaults: Option<Vec<VaultId>>,
    /// Perform for a vault only a partial sync so that only the specified records
    /// are copied.
    pub select_records: HashMap<VaultId, Vec<RecordId>>,
    /// Map the `VaultId` from the source to a local `VaultId`.
    /// If no mapping is set for a vault it assumes that the `VaultId` is the same
    /// on source and target.
    pub map_vaults: HashMap<VaultId, VaultId>,
    /// Policy if a record exists both, at source and the target, with different
    /// content.
    pub merge_policy: MergePolicy,
}
pub enum KeyProvider<'a> {
    KeyStore(RwLockReadGuard<'a, KeyStore<Provider>>),
    KeyMap(&'a HashMap<VaultId, Key<Provider>>),
}

pub trait SyncClients<'a> {
    type Db: Deref<Target = DbView<Provider>>;

    fn get_db(&'a self) -> Self::Db;
    fn get_key_provider(&'a self) -> KeyProvider<'a>;

    fn get_hierarchy(&'a self, vaults: Option<Vec<VaultId>>) -> HashMap<VaultId, Vec<(RecordId, BlobId)>> {
        let db = self.get_db();
        let key_provider = self.get_key_provider();
        let vaults = vaults.unwrap_or_else(|| db.list_vaults());
        vaults
            .into_iter()
            .map(|vid| {
                let list = match &key_provider {
                    KeyProvider::KeyStore(ks) => {
                        let key = ks.get_key(vid).unwrap();
                        db.list_records_with_blob_id(&key, vid).unwrap()
                    }
                    KeyProvider::KeyMap(map) => {
                        let key = map.get(&vid).unwrap();
                        db.list_records_with_blob_id(key, vid).unwrap()
                    }
                };
                (vid, list)
            })
            .collect()
    }

    fn get_diff(
        &'a self,
        other: HashMap<VaultId, Vec<(RecordId, BlobId)>>,
        config: &SyncClientsConfig,
    ) -> HashMap<VaultId, Vec<RecordId>> {
        let db = self.get_db();
        let key_provider = self.get_key_provider();
        other
            .into_iter()
            .filter_map(|(vid, list)| {
                if let Some(select_vaults) = config.select_vaults.as_ref() {
                    if !select_vaults.contains(&vid) {
                        return None;
                    }
                }
                let mapped_vid = config.map_vaults.get(&vid).copied().unwrap_or(vid);
                if !db.contains_vault(&mapped_vid) {
                    let diff = list.into_iter().map(|(rid, _)| rid).collect();
                    return Some((vid, diff));
                }
                let select_records = config.select_records.get(&vid);
                let diff = list
                    .into_iter()
                    .filter_map(|(rid, bid)| {
                        if let Some(select_records) = select_records {
                            if !select_records.contains(&rid) {
                                return None;
                            }
                        }
                        if !db.contains_record(mapped_vid, rid) {
                            return Some(rid);
                        }
                        if matches!(config.merge_policy, MergePolicy::KeepOld) {
                            return None;
                        }
                        match &key_provider {
                            KeyProvider::KeyStore(ks) => {
                                let target_key = ks.get_key(vid).unwrap();
                                if db.get_blob_id(&target_key, mapped_vid, rid).unwrap() == bid {
                                    return None;
                                }
                            }
                            KeyProvider::KeyMap(map) => {
                                let target_key = map.get(&vid).unwrap();
                                if db.get_blob_id(target_key, mapped_vid, rid).unwrap() == bid {
                                    return None;
                                }
                            }
                        }
                        Some(rid)
                    })
                    .collect();
                Some((vid, diff))
            })
            .collect()
    }

    fn export_entries(&'a self, select: HashMap<VaultId, Vec<RecordId>>) -> HashMap<VaultId, Vec<(RecordId, Record)>> {
        let db = self.get_db();
        select
            .into_iter()
            .map(|(vid, select)| (vid, db.export_records(vid, select).unwrap()))
            .collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncSnapshotsConfig {
    pub select_clients: Option<Vec<ClientId>>,
    pub client_config: HashMap<ClientId, SyncClientsConfig>,
    pub map_clients: HashMap<ClientId, ClientId>,
    pub merge_policy: MergePolicy,
}

pub trait SyncSnapshots {
    fn clients(&self) -> Vec<ClientId>;
    fn get_from_state<F, T>(&self, cid: ClientId, f: F) -> T
    where
        F: FnOnce(Option<&ClientState>) -> T;
    fn update_state<F, T>(&mut self, cid: ClientId, f: F)
    where
        F: FnOnce(&mut ClientState) -> T;

    fn get_hierarchy(
        &self,
        clients: Option<Vec<ClientId>>,
    ) -> HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>> {
        let clients = clients.unwrap_or_else(|| self.clients());
        clients
            .into_iter()
            .filter_map(|cid| {
                let f = |state: Option<&ClientState>| {
                    let state = state?;
                    Some(state.get_hierarchy(None))
                };
                let client_hierarchy = self.get_from_state(cid, f)?;
                Some((cid, client_hierarchy))
            })
            .collect()
    }

    fn get_diff(
        &self,
        other: HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>>,
        config: &SyncSnapshotsConfig,
    ) -> HashMap<ClientId, HashMap<VaultId, Vec<RecordId>>> {
        other
            .into_iter()
            .filter_map(|(cid, hierarchy)| {
                if let Some(select_clients) = config.select_clients.as_ref() {
                    if !select_clients.contains(&cid) {
                        return None;
                    }
                }
                let mapped_cid = config.map_clients.get(&cid).copied().unwrap_or(cid);
                let f = |state: Option<&ClientState>| {
                    let state = state?;
                    let client_diff = match config.client_config.get(&cid) {
                        Some(c) => state.get_diff(hierarchy, c),
                        None => {
                            let config = SyncClientsConfig {
                                merge_policy: config.merge_policy,
                                ..Default::default()
                            };
                            state.get_diff(hierarchy, &config)
                        }
                    };
                    Some(client_diff)
                };
                let client_diff = self.get_from_state(cid, f)?;
                Some((cid, client_diff))
            })
            .collect()
    }

    fn export_entries(
        &self,
        select: HashMap<ClientId, HashMap<VaultId, Vec<RecordId>>>,
    ) -> HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, Record)>>> {
        select
            .into_iter()
            .filter_map(|(cid, select)| {
                let f = |state: Option<&ClientState>| {
                    let state = state?;
                    Some(state.export_entries(select))
                };
                let exported = self.get_from_state(cid, f)?;
                Some((cid, exported))
            })
            .collect()
    }

    fn import_records(
        &mut self,
        records: HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, Record)>>>,
        old_keys: &HashMap<ClientId, HashMap<VaultId, Key<Provider>>>,
        config: &SyncSnapshotsConfig,
    ) {
        records.into_iter().for_each(|(cid, records)| {
            if let Some(select_clients) = config.select_clients.as_ref() {
                if !select_clients.contains(&cid) {
                    return;
                }
            }
            let old_keystore = match old_keys.get(&cid) {
                Some(k) => k,
                None => return,
            };
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
                    let old_key = old_keystore.get(&vid).unwrap();
                    let new_key = state.0.get(&mapped_vid).unwrap();
                    state.1.import_records(old_key, new_key, vid, records).unwrap()
                }
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
        })
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use super::*;

    use crate::{derive_record_id, derive_vault_id, procedures::Runner, Location};
    use engine::vault::RecordHint;
    use stronghold_utils::random;

    fn test_hint() -> RecordHint {
        random::random::<[u8; 24]>().into()
    }

    fn test_value() -> Vec<u8> {
        random::bytestring(4096)
    }

    fn test_location() -> Location {
        let v_path = random::bytestring(4096);
        let r_path = random::bytestring(4096);
        Location::generic(v_path, r_path)
    }

    fn vault_path_to_id(path: &str) -> VaultId {
        derive_vault_id(path.as_bytes().to_vec())
    }

    fn r_ctr_to_id(vault_path: &str, ctr: usize) -> RecordId {
        derive_record_id(vault_path.as_bytes().to_vec(), ctr)
    }

    #[test]
    fn test_get_hierarchy() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::default();
        let hierarchy = client.get_hierarchy(None);
        assert!(hierarchy.is_empty());

        let location_1 = test_location();
        let (vid1, rid1) = location_1.resolve();
        client.write_to_vault(&location_1, test_hint(), test_value())?;

        let v_path_2 = random::bytestring(4096);
        let r_path_2 = random::bytestring(4096);
        let location_2 = Location::generic(v_path_2.clone(), r_path_2);
        let (vid2, rid2) = location_2.resolve();
        client.write_to_vault(&location_2, test_hint(), test_value())?;

        // Same vault as value nr 2.
        let r_path_3 = random::bytestring(4096);
        let location_3 = Location::generic(v_path_2, r_path_3);
        let (vid23, rid3) = location_3.resolve();
        assert_eq!(vid2, vid23);
        client.write_to_vault(&location_3, test_hint(), test_value())?;

        let hierarchy = client.get_hierarchy(None);

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

        let v_path_1 = random::bytestring(1024);
        let vid1 = derive_vault_id(v_path_1.clone());

        let v_path_2 = random::bytestring(1024);
        let vid2 = derive_vault_id(v_path_2);

        // Include vault-1 in the sync.
        config.select_vaults.as_mut().unwrap().push(vid1);
        // Map vault-1 to vault-2:
        config.map_vaults.insert(vid1, vid2);

        for i in 0..3usize {
            let location = Location::counter(v_path_1.clone(), 10 + i);
            source.write_to_vault(&location, test_hint(), test_value())?;
        }

        let v_path_3 = random::bytestring(1024);
        let vid3 = derive_vault_id(v_path_3.clone());
        // Include vault-3 in the sync, but only selected records.
        config.select_vaults.as_mut().unwrap().push(vid3);

        let mut select_records_v3 = Vec::new();

        for i in 0..3usize {
            let location = Location::counter(v_path_3.clone(), 30 + i);
            source.write_to_vault(&location, test_hint(), test_value())?;
            // Only include record-0 and record-1 in the sync.
            if i == 0 || i == 1 {
                select_records_v3.push(location.resolve().1);
            }
        }
        config.select_records.insert(vid3, select_records_v3);

        // Vault-4 is not included in the sync.
        let v_path_4 = random::bytestring(1024);
        let vid4 = derive_vault_id(v_path_4.clone());

        let v_path_5 = random::bytestring(1024);
        let vid5 = derive_vault_id(v_path_5);
        // Irrelevant mapping of vault-4 to vault-5.
        config.map_vaults.insert(vid4, vid5);

        for i in 0..3usize {
            let location = Location::counter(v_path_4.clone(), 40 + i);
            source.write_to_vault(&location, test_hint(), test_value())?;
        }

        let target = Client::default();

        let source_hierarchy_full = source.get_hierarchy(None);
        assert_eq!(source_hierarchy_full.keys().len(), 3);

        let source_hierarchy_partial = source.get_hierarchy(config.select_vaults.clone());
        assert_eq!(source_hierarchy_partial.keys().len(), 2);

        let target_hierarchy = target.get_hierarchy(None);
        assert!(target_hierarchy.is_empty());

        // Do sync.
        target.sync_with(&source, config)?;

        // Check that old state still contains all values
        let check_hierarchy = source.get_hierarchy(None);
        assert_eq!(source_hierarchy_full, check_hierarchy);

        let mut target_hierarchy = target.get_hierarchy(None);
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
                source.write_to_vault(&location, test_hint(), test_value())?;
            }
        }

        let mut source_vault_2_hierarchy = source
            .get_hierarchy(None)
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
                    target.write_to_vault(&location, test_hint(), test_value())?;
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
            .get_hierarchy(None)
            .remove(&vault_path_to_id("vault_2"))
            .and_then(|vec| vec.into_iter().find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)))
            .map(|(_, bid)| bid)
            .expect("Record does not exist.");
        let config = SyncClientsConfig {
            merge_policy: MergePolicy::KeepOld,
            ..Default::default()
        };
        target_1.sync_with(&source, config)?;
        let mut hierarchy = target_1.get_hierarchy(None);

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
        let mut hierarchy = target_2.get_hierarchy(None);

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

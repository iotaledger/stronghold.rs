// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::VaultError,
    state::{secure::SecureClient, snapshot::Snapshot},
    Provider,
};
use engine::vault::{view::Record, BlobId, ClientId, DbView, Key, RecordId, VaultId};
use std::collections::HashMap;

/// Trait for comparing the entries stored in two instances, and synchronizing them.
/// The steps for a full synchronizing an instance A with an instance B (i.g. A would like to import all records
/// from B that it does not have yet) are:
/// 1. `B::get_hierarchy` obtains the information of all entries stored in B.
/// 2. `A::get_diff` compares the hierarchy from step 1 with the local one, and selects the paths that A does not have.
/// 3. `B::export_entries` exports the entries from B that A selected in step 2.
/// 4. `A::import_entries` extends the entries in A with the entries from B.
pub trait MergeLayer {
    /// Full hierarchy of entries with Ids.
    type Hierarchy;
    /// Full hierarchy of entries with with the encrypted data.
    type Exported;
    /// Full path to one entry in the hierarchy.
    type Path;
    /// Policy for merging two conflicting instances.
    type MergePolicy;
    /// Structure from which the vault-key can be obtained in this layer.
    type KeyProvider;

    /// Get the full hierarchy with the ids of all stored entries.
    fn get_hierarchy(&self) -> Self::Hierarchy;

    /// Compare a hierarchy of entries with the local hierarchy.
    /// Returns the entries from `other` that self does not have.
    /// If a path exists both, in `self` and `other`, include the entry depending on the [`MergePolicy`].
    /// If the [`MergeLayer::Path`] differs between `self` and `other` for the same record, a mapper has to be provided
    /// to allow proper comparison.
    fn get_diff(
        &self,
        other: Self::Hierarchy,
        mapper: Option<&Mapper<Self::Path>>,
        merge_policy: &Self::MergePolicy,
    ) -> Self::Hierarchy;

    /// Export the encrypted entries that are specified in `hierarchy`.
    /// Optionally re_encrypt the entries with new keys. This is mostly relevant in a remote-sync setting, where we
    /// don't want to share out encryption keys with the remote stronghold. In this case, we can create a temporary
    /// key_provider, encrypt the records with its keys, and send this key_provider to the remote alongside with the
    /// encrypted records.
    fn export_entries(
        &self,
        hierarchy: Self::Hierarchy,
        new_key_provider: Option<&mut Self::KeyProvider>,
    ) -> Self::Exported;

    /// Import the entries from another instance. This overwrites the local locations if they already exists, therefore
    /// [`MergeLayer::get_hierarchy`] and [`MergeLayer::get_diff`] should be used beforehand to select only the entries
    /// that do not exists yet.
    ///
    /// **Note**: If the ids in the hierarchy of the exported records differs from the local ids, a mapper has to be
    /// provided in order to import each record into the correct location. Furthermore, if the vault-encryption key
    /// differs for a record (e.g. because it was stored in a different vault), the old key provider has to be
    /// provided so that the record can be decrypted and re-encrypted with the correct key.
    fn import_entries(
        &mut self,
        exported: Self::Exported,
        mapper: Option<&Mapper<Self::Path>>,
        old_key_provider: Option<&Self::KeyProvider>,
    );
}

/// Policy for deciding between two records on the same location, with different [`BlobId`]s.
#[derive(Debug, Clone, Copy)]
pub enum SelectOne {
    KeepOld,
    Replace,
}

/// Policy for selecting between two instances (e.g. client states or vaults) with the same id.
#[derive(Debug, Clone, Copy)]
pub enum SelectOrMerge<T> {
    KeepOld,
    Replace,
    /// Recursively merge inner entries.
    Merge(T),
}

/// Function for mapping the hierarchy of one [`MergeLayer`] instance to another.
/// In case of a partial sync, this function can return [`None`] so that this entry is skipped.
#[derive(Debug, Clone)]
pub struct Mapper<T> {
    f: fn(T) -> Option<T>,
}

impl<T> Default for Mapper<T> {
    fn default() -> Self {
        Self { f: |t| Some(t) }
    }
}

impl<T> Mapper<T> {
    fn map(&self, t: T) -> Option<T> {
        let f = self.f;
        f(t)
    }
}

pub struct ClientState<'a> {
    pub db: &'a mut DbView<Provider>,
    pub keystore: &'a mut HashMap<VaultId, Key<Provider>>,
}

impl<'a> From<&'a mut SecureClient> for ClientState<'a> {
    fn from(client: &'a mut SecureClient) -> Self {
        ClientState {
            db: &mut client.db,
            keystore: &mut client.keystore.store,
        }
    }
}

impl<'a, T> From<&'a mut (HashMap<VaultId, Key<Provider>>, DbView<Provider>, T)> for ClientState<'a> {
    fn from((keystore, db, _): &'a mut (HashMap<VaultId, Key<Provider>>, DbView<Provider>, T)) -> Self {
        ClientState { db, keystore }
    }
}

/// Merge two client states.
impl<'a> MergeLayer for ClientState<'a> {
    type Hierarchy = HashMap<VaultId, Vec<(RecordId, BlobId)>>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type Path = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;
    type KeyProvider = &'a mut HashMap<VaultId, Key<Provider>>;

    fn get_hierarchy(&self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let key = self.keystore.get(&vid).unwrap();
            match self.db.list_records_with_blob_id(key, vid) {
                Ok(list) => {
                    map.insert(vid, list);
                }
                Err(VaultError::VaultNotFound(_)) => {}
                e => panic!("{:?}", e),
            }
        }
        map
    }
    fn get_diff(
        &self,
        other: Self::Hierarchy,
        mapper: Option<&Mapper<Self::Path>>,
        merge_policy: &Self::MergePolicy,
    ) -> Self::Hierarchy {
        let mut diff = HashMap::<VaultId, Vec<_>>::new();
        for (vid0, records) in other {
            for (rid0, bid) in records {
                let (vid1, rid1) = match mapper {
                    Some(mapper) => match mapper.map((vid0, rid0)) {
                        Some(ids) => ids,
                        None => continue,
                    },
                    None => (vid0, rid0),
                };
                match merge_policy {
                    SelectOrMerge::KeepOld if self.db.contains_vault(&vid1) => continue,
                    SelectOrMerge::Merge(SelectOne::KeepOld) if self.db.contains_record(vid1, rid1) => continue,
                    _ => {
                        if let Some(key) = self.keystore.get(&vid1) {
                            if self.db.get_blob_id(key, vid1, rid1).unwrap() == bid {
                                continue;
                            }
                        }
                    }
                }
                let vault_entry = diff.entry(vid0).or_default();
                vault_entry.push((rid0, bid));
            }
        }
        diff
    }

    fn export_entries(
        &self,
        hierarchy: Self::Hierarchy,
        mut new_key_provider: Option<&mut Self::KeyProvider>,
    ) -> Self::Exported {
        hierarchy
            .into_iter()
            .map(|(vid, entries)| {
                let mut exported = self
                    .db
                    .export_records(vid, entries.into_iter().map(|(rid, _)| rid))
                    .unwrap();
                if let Some(new_key_provider) = new_key_provider.as_mut() {
                    let key = self.keystore.get(&vid).unwrap();
                    let new_key = new_key_provider.entry(vid).or_insert_with(Key::random);
                    exported
                        .iter_mut()
                        .try_for_each(|(rid, r)| r.update_meta(key, (*rid).into(), new_key, (*rid).into()))
                        .unwrap();
                }
                (vid, exported)
            })
            .collect()
    }

    fn import_entries(
        &mut self,
        exported: Self::Exported,
        mapper: Option<&Mapper<Self::Path>>,
        old_key_provider: Option<&Self::KeyProvider>,
    ) {
        let mapper = match mapper {
            Some(m) => m,
            None => {
                for (vid, mut entries) in exported {
                    let key = self.keystore.get(&vid).unwrap();
                    if let Some(old_key_provider) = old_key_provider.as_ref() {
                        let old_key = old_key_provider.get(&vid).unwrap();
                        if old_key != key {
                            entries
                                .iter_mut()
                                .try_for_each(|(rid, r)| r.update_meta(old_key, (*rid).into(), key, (*rid).into()))
                                .unwrap();
                        }
                    }
                    self.db.import_records(key, vid, entries).unwrap();
                }
                return;
            }
        };
        for (vid0, entries) in exported {
            for (rid0, mut record) in entries {
                let (vid1, rid1) = match mapper.map((vid0, rid0)) {
                    Some(ids) => ids,
                    None => continue,
                };
                let key = self.keystore.entry(vid1).or_insert_with(Key::random);
                if rid0 != rid1 {
                    let old_key = old_key_provider.as_ref().map(|k| k.get(&vid0).unwrap()).unwrap_or(key);
                    record.update_meta(old_key, rid0.into(), key, rid1.into()).unwrap();
                } else if let Some(old_key_provider) = old_key_provider.as_ref() {
                    let old_key = old_key_provider.get(&vid0).unwrap();
                    if old_key != key {
                        record.update_meta(old_key, rid0.into(), key, rid1.into()).unwrap();
                    }
                }
                self.db.import_records(key, vid1, vec![(rid1, record)]).unwrap();
            }
        }
    }
}

pub struct SnapshotState<'a> {
    pub client_states: HashMap<ClientId, ClientState<'a>>,
}

impl<'a> From<&'a mut Snapshot> for SnapshotState<'a> {
    fn from(snapshot: &'a mut Snapshot) -> Self {
        let client_states = snapshot
            .state
            .0
            .iter_mut()
            .map(|(&cid, (keystore, db, _))| {
                let state = ClientState { keystore, db };
                (cid, state)
            })
            .collect();
        SnapshotState { client_states }
    }
}

impl<'a> SnapshotState<'a> {
    pub fn into_key_provider(self) -> HashMap<ClientId, &'a mut HashMap<VaultId, Key<Provider>>> {
        self.client_states
            .into_iter()
            .map(|(cid, ClientState { keystore, .. })| (cid, keystore))
            .collect()
    }
}

/// Merge two snapshot states.
/// Apart from merging the state from another snapshot file into the already loaded snapshot state, this also allows
/// to import the state from remote snapshots partially or fully.
impl<'a> MergeLayer for SnapshotState<'a> {
    type Hierarchy = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Hierarchy>;
    type Exported = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Exported>;
    type Path = (ClientId, VaultId, RecordId);
    type MergePolicy = SelectOrMerge<<ClientState<'a> as MergeLayer>::MergePolicy>;
    type KeyProvider = HashMap<ClientId, <ClientState<'a> as MergeLayer>::KeyProvider>;

    fn get_hierarchy(&self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for (client_id, state) in &self.client_states {
            let vault_map = <ClientState as MergeLayer>::get_hierarchy(state);
            map.insert(*client_id, vault_map);
        }
        map
    }

    fn get_diff(
        &self,
        other: Self::Hierarchy,
        mapper: Option<&Mapper<Self::Path>>,
        merge_policy: &Self::MergePolicy,
    ) -> Self::Hierarchy {
        let mut diff = HashMap::<ClientId, HashMap<VaultId, Vec<_>>>::new();
        for (cid0, vaults) in other {
            for (vid0, records) in vaults {
                for (rid0, bid) in records {
                    let (cid1, vid1, rid1) = match mapper {
                        Some(mapper) => match mapper.map((cid0, vid0, rid0)) {
                            Some(ids) => ids,
                            None => continue,
                        },
                        None => (cid0, vid0, rid0),
                    };
                    match (self.client_states.get(&cid1), merge_policy) {
                        (Some(_), SelectOrMerge::KeepOld) => continue,
                        (Some(state), SelectOrMerge::Merge(SelectOrMerge::KeepOld))
                            if state.db.contains_vault(&vid1) =>
                        {
                            continue
                        }
                        (Some(state), SelectOrMerge::Merge(SelectOrMerge::Merge(SelectOne::KeepOld)))
                            if state.db.contains_record(vid1, rid1) =>
                        {
                            continue
                        }
                        (Some(state), _) => {
                            if let Some(key) = state.keystore.get(&vid1) {
                                if state.db.get_blob_id(key, vid1, rid1).unwrap() == bid {
                                    continue;
                                }
                            }
                        }
                        _ => {}
                    }
                    let client_entry = diff.entry(cid0).or_default();
                    let vault_entry = client_entry.entry(vid0).or_default();
                    vault_entry.push((rid0, bid));
                }
            }
        }
        diff
    }

    fn export_entries(
        &self,
        hierarchy: Self::Hierarchy,
        mut new_key_provider: Option<&mut Self::KeyProvider>,
    ) -> Self::Exported {
        hierarchy
            .into_iter()
            .map(|(cid, vaults)| {
                let state = self.client_states.get(&cid).unwrap();
                let keystore = new_key_provider
                    .as_mut()
                    .map(|key_provider| key_provider.get_mut(&cid).unwrap());
                let vaults = <ClientState as MergeLayer>::export_entries(state, vaults, keystore);
                (cid, vaults)
            })
            .collect()
    }

    fn import_entries(
        &mut self,
        exported: Self::Exported,
        mapper: Option<&Mapper<Self::Path>>,
        mut old_key_provider: Option<&Self::KeyProvider>,
    ) {
        let mapper = match mapper {
            Some(m) => m,
            None => {
                return exported.into_iter().for_each(|(cid, vaults)| {
                    let state = self.client_states.get_mut(&cid).unwrap();
                    let keystore = old_key_provider
                        .as_mut()
                        .map(|key_provider| key_provider.get(&cid).unwrap());
                    <ClientState as MergeLayer>::import_entries(state, vaults, None, keystore)
                })
            }
        };
        // Map and re-encrypt the records to the actual location and encryption key before importing them.
        for (cid0, vaults) in exported {
            let old_keystore = old_key_provider.as_ref().map(|kp| kp.get(&cid0).unwrap());
            for (vid0, records) in vaults {
                let old_key = old_keystore.map(|ks| ks.get(&vid0).unwrap());
                for (rid0, mut r) in records {
                    let (cid1, vid1, rid1) = match mapper.map((cid0, vid0, rid0)) {
                        Some(ids) => ids,
                        None => continue,
                    };
                    // TODO: spawn new client if it does not exists yet
                    let state = self.client_states.get_mut(&cid1).unwrap();
                    let new_key = state.keystore.entry(vid1).or_insert_with(Key::random);
                    if rid0 != rid1 {
                        let old_key = old_key.unwrap_or(new_key);
                        r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                    } else if let Some(old_key) = old_key {
                        if old_key != new_key {
                            r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                        }
                    }
                    state.db.import_records(new_key, vid1, vec![(rid1, r)]).unwrap();
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{procedures::Runner, state::secure::SecureClient, Location};
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
        SecureClient::derive_vault_id(path.as_bytes().to_vec())
    }

    fn record_ctr_to_id(vault_path: &str, ctr: usize) -> RecordId {
        SecureClient::derive_record_id(vault_path.as_bytes().to_vec(), ctr)
    }

    #[test]
    fn test_get_hierarchy() {
        let cid = ClientId::random::<Provider>().unwrap();
        let mut client = SecureClient::new(cid);
        let hierarchy = ClientState::from(&mut client).get_hierarchy();
        assert!(hierarchy.is_empty());

        let location_1 = test_location();
        let (vid1, rid1) = SecureClient::resolve_location(location_1.clone());
        client.write_to_vault(&location_1, test_hint(), test_value()).unwrap();

        let v_path_2 = random::bytestring(4096);
        let r_path_2 = random::bytestring(4096);
        let location_2 = Location::generic(v_path_2.clone(), r_path_2);
        let (vid2, rid2) = SecureClient::resolve_location(location_2.clone());
        client.write_to_vault(&location_2, test_hint(), test_value()).unwrap();

        // Same vault as value nr 2.
        let r_path_3 = random::bytestring(4096);
        let location_3 = Location::generic(v_path_2, r_path_3);
        let (vid23, rid3) = SecureClient::resolve_location(location_3.clone());
        assert_eq!(vid2, vid23);
        client.write_to_vault(&location_3, test_hint(), test_value()).unwrap();

        let hierarchy = ClientState::from(&mut client).get_hierarchy();

        assert_eq!(hierarchy.len(), 2);
        let records_1 = hierarchy.iter().find(|(k, _)| **k == vid1).unwrap().1;
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0].0, rid1);

        let records_2 = hierarchy.iter().find(|(k, _)| **k == vid2).unwrap().1;
        assert_eq!(records_2.len(), 2);
        assert!(records_2.iter().any(|(rid, _)| rid == &rid2));
        assert!(records_2.iter().any(|(rid, _)| rid == &rid3));
    }

    #[test]
    fn test_export_with_mapping() {
        let mapping = |(vid, rid)| {
            if vid == vault_path_to_id("vault_1") {
                if rid == record_ctr_to_id("vault_1", 11) {
                    // Map record in same vault to new record id.
                    Some((vid, record_ctr_to_id("vault_1", 111)))
                } else if rid == record_ctr_to_id("vault_1", 12) {
                    // Map record to a vault that we skipped in the sources hierarchy.
                    Some((vault_path_to_id("vault_3"), record_ctr_to_id("vault_3", 121)))
                } else if rid == record_ctr_to_id("vault_1", 13) {
                    // Map record to an entirely new vault.
                    Some((vault_path_to_id("vault_4"), record_ctr_to_id("vault_4", 13)))
                } else {
                    // Keep at same location.
                    Some((vid, rid))
                }
            } else if vid == vault_path_to_id("vault_2") {
                // Move whole vault.
                Some((vault_path_to_id("vault_5"), rid))
            } else {
                // Skip record from any source vault with path != vault_1 || vault_2.
                None
            }
        };
        let mapper = Mapper { f: mapping };

        let cid0 = ClientId::random::<Provider>().unwrap();
        let mut source = SecureClient::new(cid0);

        // Fill test vaults.
        for i in 1..4usize {
            for j in 1..5usize {
                let vault_path = format!("vault_{}", i);
                let location = Location::counter(vault_path, i * 10 + j);
                source.write_to_vault(&location, test_hint(), test_value()).unwrap();
            }
        }

        let mut target = SecureClient::new(cid0);

        let source_state = ClientState::from(&mut source);
        let mut target_state = ClientState::from(&mut target);
        let merge_policy = match random::random::<u8>() % 4 {
            0 => SelectOrMerge::KeepOld,
            1 => SelectOrMerge::Replace,
            2 => SelectOrMerge::Merge(SelectOne::KeepOld),
            3 => SelectOrMerge::Merge(SelectOne::Replace),
            _ => unreachable!("0 <= n % 4 <= 3"),
        };

        let target_hierarchy = target_state.get_hierarchy();
        assert!(target_hierarchy.is_empty());

        let hierarchy = source_state.get_hierarchy();
        let diff = target_state.get_diff(hierarchy.clone(), Some(&mapper), &merge_policy);
        let exported = source_state.export_entries(diff, None);
        target_state.import_entries(exported, Some(&mapper), Some(&source_state.keystore));

        // Check that old state still contains all values
        let check_hierarchy = source_state.get_hierarchy();
        assert_eq!(hierarchy, check_hierarchy);

        let mut target_hierarchy = target_state.get_hierarchy();
        assert_eq!(target_hierarchy.keys().len(), 4);

        // Vault-1 was partly mapped.
        let vault_1_entries = target_hierarchy.remove(&vault_path_to_id("vault_1")).unwrap();
        assert_eq!(vault_1_entries.len(), 2);
        // Record-14 was not moved.
        assert!(vault_1_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_1", 14)));
        // Record-11 was moved to counter 111.
        assert!(vault_1_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_1", 111)));

        // All records from Vault-2 were moved to Vault-5.
        assert!(!target_hierarchy.contains_key(&vault_path_to_id("vault_2")));
        let vault_5_entries = target_hierarchy.remove(&vault_path_to_id("vault_5")).unwrap();
        assert_eq!(vault_5_entries.len(), 4);
        assert!(vault_5_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_2", 21)));
        assert!(vault_5_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_2", 22)));
        assert!(vault_5_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_2", 23)));
        assert!(vault_5_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_2", 24)));

        // Vault-3 from source was skipped, but Record-12 from Vault-1 was moved to Vault-3 Record-121.
        let vault_3_entries = target_hierarchy.remove(&vault_path_to_id("vault_3")).unwrap();
        assert_eq!(vault_3_entries.len(), 1);
        assert!(vault_3_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_3", 121)));

        // Record-13 from Vault-1 was moved to new Vault-4.
        let vault_4_entries = target_hierarchy.remove(&vault_path_to_id("vault_4")).unwrap();
        assert_eq!(vault_4_entries.len(), 1);
        assert!(vault_4_entries
            .iter()
            .any(|(rid, _)| rid == &record_ctr_to_id("vault_4", 13)));
    }
}

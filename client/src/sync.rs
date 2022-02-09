// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::VaultError,
    state::{self, secure::SecureClient},
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

    /// Export the encrypted entries that are specified in `hierarchy`. If no hierarchy is specified export all entries.
    fn export_entries(&self, hierarchy: Option<Self::Hierarchy>) -> Self::Exported;

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
        merge_policy: &Self::MergePolicy,
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
    type KeyProvider = HashMap<VaultId, Key<Provider>>;

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
                        if self.db.contains_record(vid1, rid1) {
                            let key = self.keystore.get(&vid1).unwrap();
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

    fn export_entries(&self, hierarchy: Option<Self::Hierarchy>) -> Self::Exported {
        match hierarchy {
            Some(hierarchy) => hierarchy
                .into_iter()
                .map(|(vid, entries)| {
                    let exported = self
                        .db
                        .export_records(vid, entries.into_iter().map(|(rid, _)| rid))
                        .unwrap();
                    (vid, exported)
                })
                .collect(),
            None => self.db.export_all(),
        }
    }

    fn import_entries(
        &mut self,
        exported: Self::Exported,
        merge_policy: &Self::MergePolicy,
        mapper: Option<&Mapper<Self::Path>>,
        old_key_provider: Option<&Self::KeyProvider>,
    ) {
        let mut mapped: HashMap<VaultId, Vec<_>> = HashMap::new();
        match mapper {
            Some(mapper) => {
                for (vid0, entries) in exported {
                    for (rid0, mut record) in entries {
                        let (vid1, rid1) = match mapper.map((vid0, rid0)) {
                            Some(ids) => ids,
                            None => continue,
                        };
                        match merge_policy {
                            SelectOrMerge::KeepOld if self.db.contains_vault(&vid1) => continue,
                            SelectOrMerge::Merge(SelectOne::KeepOld) if self.db.contains_record(vid1, rid1) => continue,
                            _ => {}
                        }

                        // Re-encrypt record if record-id or encryption key changed.
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
                        let vault_entry = mapped.entry(vid1).or_default();
                        vault_entry.push((rid1, record));
                    }
                }
            }
            None => {
                mapped = exported
                    .into_iter()
                    .filter_map(|(vid, entries)| {
                        // Skip entries according to merge policy if the vault already exists.
                        match merge_policy {
                            SelectOrMerge::KeepOld if self.db.contains_vault(&vid) => return None,
                            _ => {}
                        }
                        self.keystore.entry(vid).or_insert_with(Key::random);
                        let new_key = self.keystore.remove(&vid).unwrap();
                        let mut old_key = old_key_provider.as_ref().map(|ks| ks.get(&vid).unwrap());
                        if old_key == Some(&new_key) {
                            old_key = None
                        }
                        let entries = entries
                            .into_iter()
                            .filter_map(|(rid, mut record)| {
                                // Skip entry according to merge policy if the record already exists.
                                match merge_policy {
                                    SelectOrMerge::Merge(SelectOne::KeepOld) if self.db.contains_record(vid, rid) => {
                                        return None;
                                    }
                                    _ => {}
                                }
                                // Update encryption key if it has changed.
                                if let Some(old_key) = old_key {
                                    record.update_meta(old_key, rid.into(), &new_key, rid.into()).unwrap();
                                }
                                Some((rid, record))
                            })
                            .collect();
                        self.keystore.insert(vid, new_key);
                        Some((vid, entries))
                    })
                    .collect();
            }
        }
        for (vid, entries) in mapped {
            let key = self.keystore.entry(vid).or_insert_with(Key::random);
            self.db
                .import_records(key, vid, entries, matches!(merge_policy, SelectOrMerge::Replace))
                .unwrap();
        }
    }
}

pub struct SnapshotState<'a> {
    pub client_states: HashMap<ClientId, ClientState<'a>>,
}

impl<'a> From<&'a mut state::snapshot::SnapshotState> for SnapshotState<'a> {
    fn from(state: &'a mut state::snapshot::SnapshotState) -> Self {
        let client_states = state
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
    pub fn into_key_provider(self) -> HashMap<ClientId, &'a HashMap<VaultId, Key<Provider>>> {
        self.client_states
            .into_iter()
            .map(|(cid, ClientState { keystore, .. })| (cid, &*keystore))
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
    type KeyProvider = HashMap<ClientId, &'a <ClientState<'a> as MergeLayer>::KeyProvider>;

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
                            // Skip entries that are filtered by the mapper.
                            None => continue,
                        },
                        None => (cid0, vid0, rid0),
                    };
                    // Skip entries that already exists according to the merge policy.
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

    fn export_entries(&self, hierarchy: Option<Self::Hierarchy>) -> Self::Exported {
        let hierarchy: HashMap<ClientId, Option<_>> = hierarchy
            .map(|h| h.into_iter().map(|(cid, vaults)| (cid, Some(vaults))).collect())
            .unwrap_or_else(|| self.client_states.keys().map(|cid| (*cid, None)).collect());
        hierarchy
            .into_iter()
            .map(|(cid, vaults)| {
                let state = self.client_states.get(&cid).unwrap();
                let vaults = <ClientState as MergeLayer>::export_entries(state, vaults);
                (cid, vaults)
            })
            .collect()
    }

    fn import_entries(
        &mut self,
        exported: Self::Exported,
        merge_policy: &Self::MergePolicy,
        mapper: Option<&Mapper<Self::Path>>,
        mut old_key_provider: Option<&Self::KeyProvider>,
    ) {
        let mut mapped: HashMap<ClientId, HashMap<VaultId, Vec<_>>> = HashMap::new();
        match mapper {
            Some(mapper) => {
                for (cid0, vaults) in exported {
                    for (vid0, entries) in vaults {
                        for (rid0, mut record) in entries {
                            let (cid1, vid1, rid1) = match mapper.map((cid0, vid0, rid0)) {
                                Some(ids) => ids,
                                None => continue,
                            };
                            // Check for each layer (client, vault, record) the merge policy and if the entry already
                            // exists.
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
                                _ => {}
                            }
                            let state = self.client_states.get_mut(&cid1).unwrap();
                            let new_key = state.keystore.entry(vid1).or_insert_with(Key::random);
                            let old_key = old_key_provider
                                .as_ref()
                                .and_then(|kp| kp.get(&cid0))
                                .map(|ks| ks.get(&vid0).unwrap());

                            // Re-encrypt record if record-id or encryption key changed.
                            if rid0 != rid1 {
                                let old_key = old_key.unwrap_or(new_key);
                                record.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                            } else if let Some(old_key) = old_key {
                                if old_key != new_key {
                                    record.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                                }
                            }
                            let client_entry = mapped.entry(cid1).or_default();
                            let vault_entry = client_entry.entry(vid1).or_default();
                            vault_entry.push((rid1, record));
                        }
                    }
                }
                // Already re-encrypted all records, therefore no re-encryption needed in recursion anymore.
                old_key_provider = None
            }
            None => {
                mapped = exported
                    .into_iter()
                    .filter_map(|(cid, vaults)| match merge_policy {
                        SelectOrMerge::KeepOld if self.client_states.contains_key(&cid) => None,
                        _ => Some((cid, vaults)),
                    })
                    .collect();
            }
        };
        let merge_policy = match merge_policy {
            SelectOrMerge::Merge(inner) => inner,
            // In case of policy SelectOrMerge::KeepOld we have already filtered out all clients that already exist.
            _ => &SelectOrMerge::Replace,
        };
        for (cid, vaults) in mapped {
            let state = self.client_states.get_mut(&cid).unwrap();
            let old_keystore = match old_key_provider {
                Some(kp) => kp.get(&cid).copied(),
                None => None,
            };
            // let old_keystore = old_key_provider.as_ref().map(|kp| kp.get_mut(&cid).unwrap());
            <ClientState as MergeLayer>::import_entries(state, vaults, merge_policy, None, old_keystore);
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

    fn r_ctr_to_id(vault_path: &str, ctr: usize) -> RecordId {
        SecureClient::derive_record_id(vault_path.as_bytes().to_vec(), ctr)
    }

    fn perform_sync(
        source: &mut ClientState,
        target: &mut ClientState,
        mapper: Option<&Mapper<(VaultId, RecordId)>>,
        merge_policy: SelectOrMerge<SelectOne>,
    ) {
        let hierarchy = source.get_hierarchy();
        let diff = target.get_diff(hierarchy, mapper, &merge_policy);
        let exported = source.export_entries(Some(diff));
        target.import_entries(exported, &merge_policy, mapper, Some(&*source.keystore))
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
                if rid == r_ctr_to_id("vault_1", 11) {
                    // Map record in same vault to new record id.
                    Some((vid, r_ctr_to_id("vault_1", 111)))
                } else if rid == r_ctr_to_id("vault_1", 12) {
                    // Map record to a vault that we skipped in the sources hierarchy.
                    Some((vault_path_to_id("vault_3"), r_ctr_to_id("vault_3", 121)))
                } else if rid == r_ctr_to_id("vault_1", 13) {
                    // Map record to an entirely new vault.
                    Some((vault_path_to_id("vault_4"), r_ctr_to_id("vault_4", 13)))
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
        let mut source_client = SecureClient::new(cid0);

        // Fill test vaults.
        for i in 1..4usize {
            for j in 1..5usize {
                let vault_path = format!("vault_{}", i);
                let location = Location::counter(vault_path, i * 10 + j);
                source_client
                    .write_to_vault(&location, test_hint(), test_value())
                    .unwrap();
            }
        }

        let mut target_client = SecureClient::new(cid0);

        let mut source = ClientState::from(&mut source_client);
        let mut target = ClientState::from(&mut target_client);
        let merge_policy = match random::random::<u8>() % 4 {
            0 => SelectOrMerge::KeepOld,
            1 => SelectOrMerge::Replace,
            2 => SelectOrMerge::Merge(SelectOne::KeepOld),
            3 => SelectOrMerge::Merge(SelectOne::Replace),
            _ => unreachable!("0 <= n % 4 <= 3"),
        };

        let source_hierarchy = source.get_hierarchy();
        let target_hierarchy = target.get_hierarchy();
        assert!(target_hierarchy.is_empty());

        // Do sync.
        perform_sync(&mut source, &mut target, Some(&mapper), merge_policy);

        // Check that old state still contains all values
        let check_hierarchy = source.get_hierarchy();
        assert_eq!(source_hierarchy, check_hierarchy);

        let mut target_hierarchy = target.get_hierarchy();
        assert_eq!(target_hierarchy.keys().len(), 4);

        // Vault-1 was partly mapped.
        let v_1_entries = target_hierarchy.remove(&vault_path_to_id("vault_1")).unwrap();
        assert_eq!(v_1_entries.len(), 2);
        // Record-14 was not moved.
        assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 14)));
        // Record-11 was moved to counter 111.
        assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 111)));

        // All records from Vault-2 were moved to Vault-5.
        assert!(!target_hierarchy.contains_key(&vault_path_to_id("vault_2")));
        let v_5_entries = target_hierarchy.remove(&vault_path_to_id("vault_5")).unwrap();
        assert_eq!(v_5_entries.len(), 4);
        assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
        assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)));
        assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
        assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 24)));

        // Vault-3 from source was skipped, but Record-12 from Vault-1 was moved to Vault-3 Record-121.
        let v_3_entries = target_hierarchy.remove(&vault_path_to_id("vault_3")).unwrap();
        assert_eq!(v_3_entries.len(), 1);
        assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 121)));

        // Record-13 from Vault-1 was moved to new Vault-4.
        let v_4_entries = target_hierarchy.remove(&vault_path_to_id("vault_4")).unwrap();
        assert_eq!(v_4_entries.len(), 1);
        assert!(v_4_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_4", 13)));
    }

    #[test]
    fn test_merge_policy() {
        let cid0 = ClientId::random::<Provider>().unwrap();
        let mut source_client = SecureClient::new(cid0);

        // Fill test vaults.
        for i in 1..3usize {
            for j in 1..3usize {
                let vault_path = format!("vault_{}", i);
                let location = Location::counter(vault_path, i * 10 + j);
                source_client
                    .write_to_vault(&location, test_hint(), test_value())
                    .unwrap();
            }
        }

        let mut source = ClientState::from(&mut source_client);
        let mut source_vault_2_hierarchy = source.get_hierarchy().remove(&vault_path_to_id("vault_2")).unwrap();
        source_vault_2_hierarchy.sort();
        let source_v2_r2_bid = source_vault_2_hierarchy
            .iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| *bid)
            .unwrap();

        let set_up_target = || {
            let mut target_client = SecureClient::new(cid0);
            for i in 2..4usize {
                for j in 2..4usize {
                    let vault_path = format!("vault_{}", i);
                    let location = Location::counter(vault_path, i * 10 + j);
                    target_client
                        .write_to_vault(&location, test_hint(), test_value())
                        .unwrap();
                }
            }
            target_client
        };

        let assert_for_distinct_vaults = |hierarchy: &mut HashMap<VaultId, Vec<(RecordId, BlobId)>>| {
            // Imported full vault-1;
            assert_eq!(hierarchy.keys().len(), 3);
            let v_1_entries = hierarchy.remove(&vault_path_to_id("vault_1")).unwrap();
            assert_eq!(v_1_entries.len(), 2);
            assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 11)));
            assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 12)));

            // Kept old vault-3;
            let v_3_entries = hierarchy.remove(&vault_path_to_id("vault_3")).unwrap();
            assert_eq!(v_3_entries.len(), 2);
            assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 32)));
            assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 33)));
        };

        // == Test merge policy SelectOrMerge::KeepOld

        let mut target_client_1 = set_up_target();
        let mut target_1 = ClientState::from(&mut target_client_1);
        let mut old_vault_2_hierarchy = target_1.get_hierarchy().remove(&vault_path_to_id("vault_2")).unwrap();
        old_vault_2_hierarchy.sort();
        let merge_policy = SelectOrMerge::KeepOld;

        perform_sync(&mut source, &mut target_1, None, merge_policy);

        let mut hierarchy_1 = target_1.get_hierarchy();

        assert_for_distinct_vaults(&mut hierarchy_1);

        // Kept old vault-2.
        let mut v_2_entries = hierarchy_1.remove(&vault_path_to_id("vault_2")).unwrap();
        v_2_entries.sort();
        assert_eq!(v_2_entries, old_vault_2_hierarchy);

        // == Test merge policy SelectOrMerge::Replace

        let mut target_client_2 = set_up_target();
        let mut target_2 = ClientState::from(&mut target_client_2);
        let merge_policy = SelectOrMerge::Replace;
        perform_sync(&mut source, &mut target_2, None, merge_policy);
        let mut hierarchy_2 = target_2.get_hierarchy();

        assert_for_distinct_vaults(&mut hierarchy_2);

        // Replace vault-2 completely with imported one;
        let mut v_2_entries = hierarchy_2.remove(&vault_path_to_id("vault_2")).unwrap();
        v_2_entries.sort();
        assert_eq!(v_2_entries, source_vault_2_hierarchy);

        // == Test merge policy SelectOrMerge::Merge(SelectOne::KeepOld)

        let mut target_client_3 = set_up_target();
        let mut target_3 = ClientState::from(&mut target_client_3);
        let old_v2_r2_bid = target_3
            .get_hierarchy()
            .remove(&vault_path_to_id("vault_2"))
            .and_then(|vec| vec.into_iter().find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)))
            .map(|(_, bid)| bid)
            .unwrap();
        let merge_policy = SelectOrMerge::Merge(SelectOne::KeepOld);
        perform_sync(&mut source, &mut target_3, None, merge_policy);
        let mut hierarchy_3 = target_3.get_hierarchy();

        assert_for_distinct_vaults(&mut hierarchy_3);

        // Merge vault-2 with imported one, keep old record on conflict.
        let v_2_entries = hierarchy_3.remove(&vault_path_to_id("vault_2")).unwrap();
        assert_eq!(v_2_entries.len(), 3);
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
        let v2_r2_bid = v_2_entries
            .into_iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| bid)
            .unwrap();
        assert_eq!(v2_r2_bid, old_v2_r2_bid);

        // == Test merge policy SelectOrMerge::Merge(SelectOne::Replace)

        let mut target_client_4 = set_up_target();
        let mut target_4 = ClientState::from(&mut target_client_4);
        let merge_policy = SelectOrMerge::Merge(SelectOne::Replace);
        perform_sync(&mut source, &mut target_4, None, merge_policy);
        let mut hierarchy_4 = target_4.get_hierarchy();

        assert_for_distinct_vaults(&mut hierarchy_4);

        // Merge vault-2 with imported one, keep old record on conflict.
        let v_2_entries = hierarchy_4.remove(&vault_path_to_id("vault_2")).unwrap();
        assert_eq!(v_2_entries.len(), 3);
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
        assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
        let v2_r2_bid = v_2_entries
            .into_iter()
            .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
            .map(|(_, bid)| bid)
            .unwrap();
        assert_eq!(v2_r2_bid, source_v2_r2_bid);
    }
}

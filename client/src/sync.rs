// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
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
///
/// Note: A and B usually have different [`MergeLayer::KeyProvider`]s, therefore it is required between step 3 and 4 to
/// use [`Mapper::map_exported`] to update the encryption key with which the exported records are encrypted.
/// Furthermore, if the [`MergeLayer::Path`] generally differ between A and B for the same record,
/// [`Mapper::map_hierarchy`] allows to map one [`MergeLayer::Path`] to another.
/// [`Mapper`] implements [`Mapper`] on a client and snapshot layer, with mapping left-2-right (A to B),
/// and right-2-left (B to A). The latter returns an `Option`, with which `None` can be returned for specific entries in
/// case of a partial sync (e.g. only import a single client).
///
/// Including the mapping steps, the full flow between A and B with different [`MergeLayer::Path`] and
/// [`MergeLayer::KeyProvider`] would be:
/// 1. `B::get_hierarchy`
/// 2. `Mapper::map_hierarchy`, with MappingDirection::R2L
/// 3. `A::get_diff`
/// 4. `Mapper::map_hierarchy`, with MappingDirection::L2R
/// 5. `B::export_entries`
/// 6. `Mapper::map_exported`; always MappingDirection::R2L
/// 7. `A::import_entries`
///
/// In case of a remote sync, the mapping is done on the initiators side (= "A").
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
    /// If this hierarchy should be compared with another instances with different Ids,
    /// [`Mapper::map_hierarchy`] can be used to map the hierarchy to match the target's structure.
    fn get_hierarchy(&mut self) -> Self::Hierarchy;

    /// Compare a hierarchy of entries with the local hierarchy.
    /// Returns the entries from `other` that self does not have.
    /// If a path exists both, in `self` and `other`, include the entry depending on the [`MergePolicy`].
    /// If the [`MergeLayer::Path`] differs between `self` and `other` for the same record, a mapper has to be provided
    /// to enable proper comparison.
    fn get_diff(
        &mut self,
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
        &mut self,
        hierarchy: Self::Hierarchy,
        new_key_provider: Option<Self::KeyProvider>,
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
        old_key_provider: Option<Self::KeyProvider>,
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

/// Direction for mapping the hierarchy from one instance to another.
#[derive(Debug, Clone, Copy)]
pub enum MappingDirection {
    L2R,
    R2L,
}

/// Function for mapping the hierarchy of one [`MergeLayer`] instance to another.
/// In case of a partial sync, this function can return [`None`], so that this entry is skipped.
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

/// Merge two client states.
impl<'a> MergeLayer for ClientState<'a> {
    type Hierarchy = HashMap<VaultId, Vec<(RecordId, BlobId)>>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type Path = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;
    type KeyProvider = &'a mut HashMap<VaultId, Key<Provider>>;

    fn get_hierarchy(&mut self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let key = self.keystore.get(&vid).unwrap();
            let list = self.db.list_records_with_blob_id(key, vid).unwrap();
            map.insert(vid, list);
        }
        map
    }
    fn get_diff(
        &mut self,
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
        &mut self,
        hierarchy: Self::Hierarchy,
        mut new_key_provider: Option<Self::KeyProvider>,
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
        old_key_provider: Option<Self::KeyProvider>,
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

/// Merge two snapshot states.
/// Apart from merging the state from another snapshot file into the already loaded snapshot state, this also allows
/// to import the state from remote snapshots partially or fully.
impl<'a> MergeLayer for SnapshotState<'a> {
    type Hierarchy = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Hierarchy>;
    type Exported = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Exported>;
    type Path = (ClientId, VaultId, RecordId);
    type MergePolicy = SelectOrMerge<<ClientState<'a> as MergeLayer>::MergePolicy>;
    type KeyProvider = HashMap<ClientId, <ClientState<'a> as MergeLayer>::KeyProvider>;

    fn get_hierarchy(&mut self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for (client_id, state) in &mut self.client_states {
            let vault_map = <ClientState as MergeLayer>::get_hierarchy(state);
            map.insert(*client_id, vault_map);
        }
        map
    }

    fn get_diff(
        &mut self,
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
                    match (self.client_states.get_mut(&cid1), merge_policy) {
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
        &mut self,
        hierarchy: Self::Hierarchy,
        mut new_key_provider: Option<Self::KeyProvider>,
    ) -> Self::Exported {
        hierarchy
            .into_iter()
            .map(|(cid, vaults)| {
                let state = self.client_states.get_mut(&cid).unwrap();
                let keystore = new_key_provider
                    .as_mut()
                    .map(|key_provider| key_provider.remove(&cid).unwrap());
                let vaults = <ClientState as MergeLayer>::export_entries(state, vaults, keystore);
                (cid, vaults)
            })
            .collect()
    }

    fn import_entries(
        &mut self,
        exported: Self::Exported,
        mapper: Option<&Mapper<Self::Path>>,
        mut old_key_provider: Option<Self::KeyProvider>,
    ) {
        let mapper = match mapper {
            Some(m) => m,
            None => {
                return exported.into_iter().for_each(|(cid, vaults)| {
                    let state = self.client_states.get_mut(&cid).unwrap();
                    let keystore = old_key_provider
                        .as_mut()
                        .map(|key_provider| key_provider.remove(&cid).unwrap());
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

    use stronghold_utils::random;

    use crate::{procedures::Runner, state::secure::SecureClient, Location};

    use super::*;

    #[test]
    fn test_get_hierarchy() {
        let cid_a = ClientId::random::<Provider>().unwrap();
        let mut client_a = SecureClient::new(cid_a);
        let hierarchy = ClientState::from(&mut client_a).get_hierarchy();
        assert!(hierarchy.is_empty());

        let v_path_1 = random::bytestring(4096);
        let r_path_1 = random::bytestring(4096);
        let location_1 = Location::generic(v_path_1, r_path_1);
        let (vid1, rid1) = SecureClient::resolve_location(location_1.clone());
        let test_hint_1 = random::random::<[u8; 24]>().into();
        let test_value_1 = random::bytestring(4096);
        client_a.write_to_vault(&location_1, test_hint_1, test_value_1).unwrap();

        let v_path_2 = random::bytestring(4096);
        let r_path_2 = random::bytestring(4096);
        let location_2 = Location::generic(v_path_2.clone(), r_path_2);
        let (vid2, rid2) = SecureClient::resolve_location(location_2.clone());
        let test_hint_2 = random::random::<[u8; 24]>().into();
        let test_value_2 = random::bytestring(4096);
        client_a.write_to_vault(&location_2, test_hint_2, test_value_2).unwrap();

        let r_path_3 = random::bytestring(4096);
        let location_3 = Location::generic(v_path_2, r_path_3);
        let (vid23, rid3) = SecureClient::resolve_location(location_3.clone());
        assert_eq!(vid2, vid23);
        let test_hint_3 = random::random::<[u8; 24]>().into();
        let test_value_3 = random::bytestring(4096);
        client_a.write_to_vault(&location_3, test_hint_3, test_value_3).unwrap();

        let hierarchy = ClientState::from(&mut client_a).get_hierarchy();

        assert_eq!(hierarchy.len(), 2);
        let records_1 = hierarchy.iter().find(|(k, _)| **k == vid1).unwrap().1;
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0].0, rid1);

        let records_2 = hierarchy.iter().find(|(k, _)| **k == vid2).unwrap().1;
        assert_eq!(records_2.len(), 2);
        assert!(records_2.iter().any(|(rid, _)| rid == &rid2));
        assert!(records_2.iter().any(|(rid, _)| rid == &rid3));
    }
}

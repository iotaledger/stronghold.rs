// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{RecordError, VaultError},
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
/// [`BidiMapping`] implements [`Mapper`] on a client and snapshot layer, with mapping left-2-right (A to B),
/// and right-2-left (B to A). The latter returns an `Option`, with which `None` can be returned for specific entries in
/// case of a partial sync (e.g. only import a single client).
///
/// Including the mapping steps, the full flow between A and B with different [`MergeLayer::Path`] and
/// [`MergeLayer::KeyProvider`] would be:
/// 1. `B::get_hierarchy`
/// 2. `BidiMapping::map_hierarchy`, with MappingDirection::R2L
/// 3. `A::get_diff`
/// 4. `BidiMapping::map_hierarchy`, with MappingDirection::L2R
/// 5. `B::export_entries`
/// 6. `BidiMapping::map_exported`; always MappingDirection::R2L
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
    fn get_diff(&mut self, other: Self::Hierarchy, merge_policy: &Self::MergePolicy) -> Self::Hierarchy;

    /// Export the encrypted entries that are specified in `hierarchy`.
    /// If the entries are exported to a different location with different encryption key,
    /// [`Mapper::map_exported`] allows map the hierarchy of entries and re-encrypt the records with the correct key.
    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> Self::Exported;

    /// Import the entries from another instance. This overwrites the local locations if they already exists, therefore
    /// [`MergeLayer::get_hierarchy`] and [`MergeLayer::get_diff`] should be used beforehand to select only the entries
    /// that do not exists yet.
    ///
    /// **Note**: This expects that the records are encrypted with the correct vault-key as it is stored in the local
    /// `KeyStore`, and that [`RecordId`] that is encrypted within the Record blob is correct.
    /// If either the encryption key differs or the record was moved to a different [`RecordId`],
    /// [`Mapper::map_exported`] has to be called before importing the entries.
    fn import_entries(&mut self, exported: Self::Exported);
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

/// Map the hierarchy and exported entries between two instances that synchronize, for the records the
/// path or encryption key differs.
pub trait Mapper<T: MergeLayer> {
    /// Map the hierarchy stored in one instance before calculating the diff to another ([`MappingDirection::R2L`]),
    /// or after calculation the diff before exporting the entries ([`MappingDirection::L2R`]).
    fn map_hierarchy(&self, hierarchy: T::Hierarchy, di: MappingDirection) -> T::Hierarchy;

    /// Map and re-encrypt the exported entries before importing them at the target.
    /// In case of a sync with a remote [`Stronghold`], this may even be done twice: Before sending them over the wire,
    /// with an ephemeral `KeyProvider` that is send to the remove alongside with the records, and then again at the
    /// remote to the encrypt them correctly with the keys of the local `KeyProvider`.
    fn map_exported(
        &self,
        old_key_provider: T::KeyProvider,
        new_key_provider: T::KeyProvider,
        entries: T::Exported,
    ) -> T::Exported;
}

/// Direction for mapping the hierarchy from one instance to another.
#[derive(Debug, Clone, Copy)]
pub enum MappingDirection {
    L2R,
    R2L,
}

/// Bidirectional function for mapping the hierarchy of one [`MergeLayer`] instance to another.
/// Typically if an instance A would like to synchronize with an instance B  (i.g. A would like to import all records
/// from B that it does not have yet) the direction would be:
/// - A -> B: L2R ("left-to-right")
/// - B -> A: R2L ("right-to-left")
/// In case of a partial sync, direction R2L can return [`None`], so that this entry is skipped.
#[derive(Debug, Clone)]
pub struct BidiMapping<T> {
    l2r: fn(T) -> T,
    r2l: fn(T) -> Option<T>,
}

impl<T> Default for BidiMapping<T> {
    fn default() -> Self {
        Self {
            l2r: |t| t,
            r2l: |t| Some(t),
        }
    }
}

impl<T> BidiMapping<T> {
    fn map(&self, t: T, di: MappingDirection) -> Option<T> {
        match di {
            MappingDirection::L2R => {
                let f = self.l2r;
                Some(f(t))
            }
            MappingDirection::R2L => {
                let f = self.r2l;
                f(t)
            }
        }
    }
}

pub struct ClientState<'a> {
    pub db: &'a mut DbView<Provider>,
    pub keystore: &'a HashMap<VaultId, Key<Provider>>,
}

impl<'a> From<&'a mut SecureClient> for ClientState<'a> {
    fn from(client: &'a mut SecureClient) -> Self {
        ClientState {
            db: &mut client.db,
            keystore: &client.keystore.store,
        }
    }
}

/// Merge two client states.
impl<'a> MergeLayer for ClientState<'a> {
    type Hierarchy = HashMap<VaultId, Vec<(RecordId, BlobId)>>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type Path = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;
    type KeyProvider = &'a HashMap<VaultId, Key<Provider>>;

    fn get_hierarchy(&mut self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let key = self.keystore.get(&vid).unwrap();
            let list = self.db.list_records_with_blob_id(key, vid).unwrap();
            map.insert(vid, list);
        }
        map
    }
    fn get_diff(&mut self, other: Self::Hierarchy, merge_policy: &Self::MergePolicy) -> Self::Hierarchy {
        let mut diff = HashMap::new();
        for (vid, records) in other {
            let vault_merge_policy = match merge_policy {
                SelectOrMerge::KeepOld => continue,
                SelectOrMerge::Replace => {
                    diff.insert(vid, records);
                    continue;
                }
                SelectOrMerge::Merge(ref p) => p,
            };
            let key = match self.keystore.get(&vid) {
                Some(k) => k,
                None => {
                    diff.insert(vid, records);
                    continue;
                }
            };
            let mut records_diff = Vec::new();
            for (rid, blob_id) in records {
                match self.db.get_blob_id(key, vid, rid) {
                    Ok(bid) if bid == blob_id => {}
                    Ok(_) if matches!(vault_merge_policy, SelectOne::KeepOld) => {}
                    Ok(_)
                    | Err(VaultError::Record(RecordError::RecordNotFound(_)))
                    | Err(VaultError::VaultNotFound(_)) => records_diff.push((rid, blob_id)),
                    Err(VaultError::Record(_)) => todo!(),
                    Err(VaultError::Procedure(_)) => unreachable!("Infallible."),
                }
            }
            if !records_diff.is_empty() {
                diff.insert(vid, records_diff);
            }
        }
        diff
    }

    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> Self::Exported {
        hierarchy
            .into_iter()
            .map(|(vid, entries)| {
                let exported = self
                    .db
                    .export_records(vid, entries.into_iter().map(|(rid, _)| rid))
                    .unwrap();
                (vid, exported)
            })
            .collect()
    }

    fn import_entries(&mut self, exported: Self::Exported) {
        exported
            .into_iter()
            .try_for_each(|(vid, entries)| {
                let key = self.keystore.get(&vid).unwrap();
                self.db.import_records(key, vid, entries)
            })
            .unwrap();
    }
}

impl<'a> Mapper<ClientState<'a>> for BidiMapping<<ClientState<'a> as MergeLayer>::Path> {
    fn map_hierarchy(
        &self,
        hierarchy: <ClientState<'a> as MergeLayer>::Hierarchy,
        di: MappingDirection,
    ) -> <ClientState<'a> as MergeLayer>::Hierarchy {
        let mut map = HashMap::<_, Vec<_>>::new();
        for (vid0, records) in hierarchy {
            for (rid0, bid) in records {
                let (vid1, rid1) = match self.map((vid0, rid0), di) {
                    Some(ids) => ids,
                    None => continue,
                };
                let entry = map.entry(vid1).or_default();
                entry.push((rid1, bid))
            }
        }
        map
    }

    fn map_exported(
        &self,
        old_keystore: <ClientState<'a> as MergeLayer>::KeyProvider,
        new_keystore: <ClientState<'a> as MergeLayer>::KeyProvider,
        hierarchy: <ClientState<'a> as MergeLayer>::Exported,
    ) -> <ClientState<'a> as MergeLayer>::Exported {
        let mut map = HashMap::<_, Vec<_>>::new();
        let r2l = self.r2l;
        for (vid0, records) in hierarchy {
            let old_key = old_keystore.get(&vid0).unwrap();
            for (rid0, mut r) in records {
                let (vid1, rid1) = match r2l((vid0, rid0)) {
                    Some(ids) => ids,
                    None => continue,
                };
                let new_key = new_keystore.get(&vid1).unwrap();
                if old_key != new_key || rid0 != rid1 {
                    r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                }
                let entry = map.entry(vid1).or_default();
                entry.push((rid1, r))
            }
        }
        map
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

    fn get_diff(&mut self, other: Self::Hierarchy, merge_policy: &Self::MergePolicy) -> Self::Hierarchy {
        let mut diff = HashMap::new();
        for (cid, vaults) in other {
            let vault_merge_policy = match merge_policy {
                SelectOrMerge::KeepOld => continue,
                SelectOrMerge::Replace => {
                    diff.insert(cid, vaults);
                    continue;
                }
                SelectOrMerge::Merge(ref p) => p,
            };
            let state = match self.client_states.get_mut(&cid) {
                Some(state) => state,
                None => {
                    diff.insert(cid, vaults);
                    continue;
                }
            };

            let vault_diff = <ClientState as MergeLayer>::get_diff(state, vaults, vault_merge_policy);
            if !vault_diff.is_empty() {
                diff.insert(cid, vault_diff);
            }
        }
        diff
    }

    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> Self::Exported {
        hierarchy
            .into_iter()
            .map(|(cid, vaults)| {
                let state = self.client_states.get_mut(&cid).unwrap();
                let vaults = <ClientState as MergeLayer>::export_entries(state, vaults);
                (cid, vaults)
            })
            .collect()
    }

    fn import_entries(&mut self, exported: Self::Exported) {
        exported.into_iter().for_each(|(cid, vaults)| {
            let state = self.client_states.get_mut(&cid).unwrap();
            <ClientState as MergeLayer>::import_entries(state, vaults);
        });
    }
}

impl<'a> Mapper<SnapshotState<'a>> for BidiMapping<<SnapshotState<'a> as MergeLayer>::Path> {
    fn map_hierarchy(
        &self,
        hierarchy: <SnapshotState<'a> as MergeLayer>::Hierarchy,
        di: MappingDirection,
    ) -> <SnapshotState<'a> as MergeLayer>::Hierarchy {
        let mut map = HashMap::<_, HashMap<_, Vec<_>>>::new();
        for (cid0, vaults) in hierarchy {
            for (vid0, records) in vaults {
                for (rid0, bid) in records {
                    let (cid1, vid1, rid1) = match self.map((cid0, vid0, rid0), di) {
                        Some(ids) => ids,
                        None => continue,
                    };
                    let entry = map.entry(cid1).or_default();
                    let vault_entry = entry.entry(vid1).or_default();
                    vault_entry.push((rid1, bid))
                }
            }
        }
        map
    }

    fn map_exported(
        &self,
        old_key_provider: <SnapshotState<'a> as MergeLayer>::KeyProvider,
        new_key_provider: <SnapshotState<'a> as MergeLayer>::KeyProvider,
        entries: <SnapshotState<'a> as MergeLayer>::Exported,
    ) -> <SnapshotState<'a> as MergeLayer>::Exported {
        let mut map = HashMap::<_, HashMap<_, Vec<_>>>::new();
        let r2l = self.r2l;
        for (cid0, vaults) in entries {
            let old_keystore = old_key_provider.get(&cid0).unwrap();
            for (vid0, records) in vaults {
                let old_key = old_keystore.get(&vid0).unwrap();
                for (rid0, mut r) in records {
                    let (cid1, vid1, rid1) = match r2l((cid0, vid0, rid0)) {
                        Some(ids) => ids,
                        None => continue,
                    };
                    let new_keystore = new_key_provider.get(&cid0).unwrap();
                    let new_key = new_keystore.get(&vid1).unwrap();
                    if old_key != new_key || rid0 != rid1 {
                        r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                    }
                    let entry = map.entry(cid1).or_default();
                    let vault_entry = entry.entry(vid1).or_default();
                    vault_entry.push((rid1, r))
                }
            }
        }
        map
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

    #[test]
    fn test_map_hierarchy() {
        let vid1 = VaultId::random::<Provider>().unwrap();
        let rid1 = RecordId::random::<Provider>().unwrap();
        let bid1 = BlobId::random::<Provider>().unwrap();

        let vid2 = VaultId::random::<Provider>().unwrap();
        let rid2 = RecordId::random::<Provider>().unwrap();
        let bid2 = BlobId::random::<Provider>().unwrap();

        let vid3 = VaultId::random::<Provider>().unwrap();
        let rid3 = RecordId::random::<Provider>().unwrap();
        let bid3 = BlobId::random::<Provider>().unwrap();

        let mut hierarchy = HashMap::new();
        hierarchy.insert(vid1, vec![(rid1, bid1)]);
        hierarchy.insert(vid2, vec![(rid2, bid2)]);
        hierarchy.insert(vid3, vec![(rid3, bid3)]);

        // Map all records into same vault.
        let l2r = |(_, rid)| (SecureClient::derive_vault_id("test".as_bytes().to_vec()), rid);

        let mapper = BidiMapping::<(VaultId, RecordId)> { l2r, r2l: |_| None };
        let mut mapped = mapper.map_hierarchy(hierarchy, MappingDirection::L2R);
        let expect_vault = SecureClient::derive_vault_id("test".as_bytes().to_vec());
        let records = mapped.remove(&expect_vault).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.contains(&(rid1, bid1)));
        assert!(records.contains(&(rid2, bid2)));
        assert!(records.contains(&(rid3, bid3)));
        assert!(mapped.is_empty());
    }
}

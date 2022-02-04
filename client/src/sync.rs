// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{RecordError, VaultError},
    Provider,
};
use engine::vault::{view::Record, BlobId, ClientId, DbView, Key, RecordId, VaultId};
use std::collections::HashMap;

pub trait MergeLayer {
    type Hierarchy;
    type Exported;
    type Mapping;
    type MergePolicy;
    type KeyProvider;

    fn get_hierarchy(&mut self) -> Self::Hierarchy;
    fn get_diff(&mut self, other: Self::Hierarchy, merge_policy: &Self::MergePolicy) -> Self::Hierarchy;
    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> Self::Exported;
    fn import_entries(&mut self, exported: Self::Exported);
}

#[derive(Debug, Clone, Copy)]
pub enum SelectOne {
    KeepOld,
    Replace,
}

#[derive(Debug, Clone, Copy)]
pub enum SelectOrMerge<T> {
    KeepOld,
    Replace,
    Merge(T),
}

#[derive(Debug, Clone, Copy)]
pub enum Di {
    L2R,
    R2L,
}

#[derive(Debug, Clone)]
pub struct BidiMapping<T> {
    l2r: fn(T) -> Option<T>,
    r2l: fn(T) -> T,
}

impl<T> Default for BidiMapping<T> {
    fn default() -> Self {
        Self {
            l2r: |t| Some(t),
            r2l: |t| t,
        }
    }
}

impl<T> BidiMapping<T> {
    fn map(&self, t: T, di: Di) -> Option<T> {
        match di {
            Di::L2R => {
                let f = self.l2r;
                f(t)
            }
            Di::R2L => {
                let f = self.r2l;
                Some(f(t))
            }
        }
    }
}

pub trait Mapper<T: MergeLayer> {
    fn map_hierarchy(&self, hierarchy: T::Hierarchy, di: Di) -> T::Hierarchy;

    fn map_exported(
        &self,
        old_keystore: T::KeyProvider,
        new_keystore: T::KeyProvider,
        entries: T::Exported,
    ) -> T::Exported;
}

pub struct ClientState<'a> {
    pub db: &'a mut DbView<Provider>,
    pub keystore: &'a HashMap<VaultId, Key<Provider>>,
}

impl<'a> MergeLayer for ClientState<'a> {
    type Hierarchy = HashMap<VaultId, Vec<(RecordId, BlobId)>>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type Mapping = (VaultId, RecordId);
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

impl<'a> Mapper<ClientState<'a>> for BidiMapping<<ClientState<'a> as MergeLayer>::Mapping> {
    fn map_hierarchy(
        &self,
        hierarchy: <ClientState<'a> as MergeLayer>::Hierarchy,
        di: Di,
    ) -> <ClientState<'a> as MergeLayer>::Hierarchy {
        let mut map = HashMap::<_, Vec<_>>::new();
        for (vid0, records) in hierarchy {
            for (rid0, bid) in records {
                if let Some((vid1, rid1)) = self.map((vid0, rid0), di) {
                    let entry = map.entry(vid1).or_default();
                    entry.push((rid1, bid))
                }
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
                let (vid1, rid1) = r2l((vid0, rid0));
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

impl<'a> MergeLayer for SnapshotState<'a> {
    type Hierarchy = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Hierarchy>;
    type Exported = HashMap<ClientId, <ClientState<'a> as MergeLayer>::Exported>;
    type Mapping = (ClientId, VaultId, RecordId);
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

impl<'a> Mapper<SnapshotState<'a>> for BidiMapping<<SnapshotState<'a> as MergeLayer>::Mapping> {
    fn map_hierarchy(
        &self,
        hierarchy: <SnapshotState<'a> as MergeLayer>::Hierarchy,
        di: Di,
    ) -> <SnapshotState<'a> as MergeLayer>::Hierarchy {
        let mut map = HashMap::<_, HashMap<_, Vec<_>>>::new();
        for (cid0, vaults) in hierarchy {
            for (vid0, records) in vaults {
                for (rid0, bid) in records {
                    if let Some((cid1, vid1, rid1)) = self.map((cid0, vid0, rid0), di) {
                        let entry = map.entry(cid1).or_default();
                        let vault_entry = entry.entry(vid1).or_default();
                        vault_entry.push((rid1, bid))
                    }
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
                    let (cid1, vid1, rid1) = r2l((cid0, vid0, rid0));
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

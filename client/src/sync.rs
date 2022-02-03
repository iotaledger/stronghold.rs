// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{RecordError, VaultError},
    state::{key_store::KeyStore, secure::SecureClient, snapshot::Snapshot},
    Provider,
};
use engine::vault::{view::Record, BlobId, ClientId, DbView, RecordId, VaultId};
use std::collections::HashMap;

pub trait MergeLayer {
    type Hierarchy;
    type Exported;
    type Mapping;
    type MergePolicy;

    fn get_hierarchy(&mut self) -> Self::Hierarchy;
    fn get_diff(&mut self, other: Self::Hierarchy, merge_policy: &Self::MergePolicy) -> Self::Hierarchy;
    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> (&KeyStore, Self::Exported);
    fn import_entries(&mut self, key_store: &KeyStore, exported: Self::Exported);
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

    fn map_exported(&self, old_keystore: &KeyStore, new_keystore: &KeyStore, entries: T::Exported) -> T::Exported;
}

impl MergeLayer for SecureClient {
    type Hierarchy = HashMap<VaultId, Vec<(RecordId, BlobId)>>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type Mapping = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;

    fn get_hierarchy(&mut self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let key = self.keystore.get_key(vid).unwrap();
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
            let key = match self.keystore.get_key(vid) {
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

    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> (&KeyStore, Self::Exported) {
        let map = hierarchy
            .into_iter()
            .map(|(vid, entries)| {
                let exported = self
                    .db
                    .export_records(vid, entries.into_iter().map(|(rid, _)| rid))
                    .unwrap();
                (vid, exported)
            })
            .collect();
        (&self.keystore, map)
    }

    fn import_entries(&mut self, key_store: &KeyStore, exported: Self::Exported) {
        exported
            .into_iter()
            .try_for_each(|(vid, entries)| {
                let key = key_store.get_key(vid).unwrap();
                self.db.import_records(key, vid, entries)
            })
            .unwrap();
    }
}

impl Mapper<SecureClient> for BidiMapping<<SecureClient as MergeLayer>::Mapping> {
    fn map_hierarchy(
        &self,
        hierarchy: <SecureClient as MergeLayer>::Hierarchy,
        di: Di,
    ) -> <SecureClient as MergeLayer>::Hierarchy {
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
        old_keystore: &KeyStore,
        new_keystore: &KeyStore,
        hierarchy: <SecureClient as MergeLayer>::Exported,
    ) -> <SecureClient as MergeLayer>::Exported {
        let mut map = HashMap::<_, Vec<_>>::new();
        let r2l = self.r2l;
        for (vid0, records) in hierarchy {
            let old_key = old_keystore.get_key(vid0).unwrap();
            for (rid0, mut r) in records {
                let (vid1, rid1) = r2l((vid0, rid0));
                let new_key = new_keystore.get_key(vid1).unwrap();
                r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                let entry = map.entry(vid1).or_default();
                entry.push((rid1, r))
            }
        }
        map
    }
}

impl MergeLayer for Snapshot {
    type Hierarchy = HashMap<ClientId, <SecureClient as MergeLayer>::Hierarchy>;
    type Exported = HashMap<ClientId, <SecureClient as MergeLayer>::Exported>;
    type Mapping = (ClientId, VaultId, RecordId);
    type MergePolicy = SelectOrMerge<<SecureClient as MergeLayer>::MergePolicy>;

    fn get_hierarchy(&mut self) -> Self::Hierarchy {
        let mut map = HashMap::new();
        for (client_id, (keystore, db, _)) in &mut self.state.0 {
            let mut vault_map = HashMap::new();
            for vid in db.list_vaults() {
                let key = keystore.get(&vid).unwrap();
                let list = db.list_records_with_blob_id(key, vid).unwrap();
                vault_map.insert(vid, list);
            }
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
            let (keystore, db) = match self.state.0.get_mut(&cid) {
                Some((k, db, _)) => (k, db),
                None => {
                    diff.insert(cid, vaults);
                    continue;
                }
            };

            let mut vault_diff = HashMap::new();
            for (vid, records) in vaults {
                let record_merge_policy = match vault_merge_policy {
                    SelectOrMerge::KeepOld => continue,
                    SelectOrMerge::Replace => {
                        vault_diff.insert(vid, records);
                        continue;
                    }
                    SelectOrMerge::Merge(ref p) => p,
                };
                let key = match keystore.get(&vid) {
                    Some(k) => k,
                    None => {
                        vault_diff.insert(vid, records);
                        continue;
                    }
                };

                let mut records_diff = Vec::new();
                for (rid, blob_id) in records {
                    match db.get_blob_id(key, vid, rid) {
                        Ok(bid) if bid == blob_id => {}
                        Ok(_) if matches!(record_merge_policy, SelectOne::KeepOld) => {}
                        Ok(_)
                        | Err(VaultError::Record(RecordError::RecordNotFound(_)))
                        | Err(VaultError::VaultNotFound(_)) => records_diff.push((rid, blob_id)),
                        Err(VaultError::Record(_)) => todo!(),
                        Err(VaultError::Procedure(_)) => unreachable!("Infallible."),
                    }
                }
                if !records_diff.is_empty() {
                    vault_diff.insert(vid, records_diff);
                }
            }
        }
        diff
    }

    fn export_entries(&mut self, hierarchy: Self::Hierarchy) -> (&KeyStore, Self::Exported) {
        let map = hierarchy
            .into_iter()
            .filter_map(|(cid, vaults)| {
                let (keystore, db, _) = self.state.0.get_mut(&cid)?;
                let vaults = vaults
                    .into_iter()
                    .map(|(vid, entries)| {
                        let exported = db.export_records(vid, entries.into_iter().map(|(rid, _)| rid)).unwrap();
                        (vid, exported)
                    })
                    .collect();
                Some((cid, vaults))
            })
            .collect();
        let keystore: &KeyStore = todo!();
        (keystore, map)
    }

    fn import_entries(&mut self, key_store: &KeyStore, exported: Self::Exported) {
        exported
            .into_iter()
            .try_for_each(|(cid, vaults)| {
                vaults.into_iter().try_for_each(|(vid, entries)| {
                    let key = key_store.get_key(vid).unwrap();
                    let db: &mut DbView<Provider> = todo!();
                    db.import_records(key, vid, entries)
                })
            })
            .unwrap();
    }
}

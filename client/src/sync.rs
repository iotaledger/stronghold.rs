// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{RecordError, VaultError},
    state::{key_store::KeyStore, secure::SecureClient},
    Provider,
};
use engine::vault::{view::Record, BlobId, ClientId, Key, RecordId, VaultId};
use std::collections::HashMap;

pub struct BidiMapping<T> {
    l2r: fn(T) -> T,
    r2l: fn(T) -> T,
}

impl<T> BidiMapping<T> {
    fn map(&self, t: T, di: Di) -> T {
        let f = match di {
            Di::L2R => self.l2r,
            Di::R2L => self.r2l,
        };
        f(t)
    }
}

trait Mapper<T: Layer> {
    fn map_hierarchy(&self, hierarchy: T::Hierarchy, di: Di) -> T::Hierarchy;

    fn map_exported(
        &self,
        old_key_provider: &T::KeyProvider,
        old_key_provider: &T::KeyProvider,
        di: Di,
        entries: T::Exported,
    ) -> T::Exported;
}

#[derive(Debug, Clone, Copy)]
enum Di {
    L2R,
    R2L,
}

impl Mapper<VaultLayer> for BidiMapping<<VaultLayer as Layer>::Mapping> {
    fn map_hierarchy(&self, hierarchy: <VaultLayer as Layer>::Hierarchy, di: Di) -> <VaultLayer as Layer>::Hierarchy {
        hierarchy
            .into_iter()
            .map(|(rid, bid)| (self.map(rid, di), bid))
            .collect()
    }

    fn map_exported(
        &self,
        old_key: &<VaultLayer as Layer>::KeyProvider,
        new_key: &<VaultLayer as Layer>::KeyProvider,
        di: Di,
        mut entries: <VaultLayer as Layer>::Exported,
    ) -> <VaultLayer as Layer>::Exported {
        entries
            .iter_mut()
            .try_for_each(|(rid, r)| r.update_meta(old_key, (*rid).into(), new_key, self.map(*rid, di).into()))
            .unwrap();
        entries
    }
}

impl Mapper<ClientLayer> for BidiMapping<<ClientLayer as Layer>::Mapping> {
    fn map_hierarchy(&self, hierarchy: <ClientLayer as Layer>::Hierarchy, di: Di) -> <ClientLayer as Layer>::Hierarchy {
        let mut map = HashMap::<_, Vec<_>>::new();
        for (vid0, records) in hierarchy {
            for (rid0, bid) in records {
                let (vid1, rid1) = self.map((vid0, rid0), di);
                let entry = map.entry(vid1).or_default();
                entry.push((rid1, bid))
            }
        }
        map
    }

    fn map_exported(
        &self,
        old_keystore: &<ClientLayer as Layer>::KeyProvider,
        new_keystore: &<ClientLayer as Layer>::KeyProvider,
        di: Di,
        hierarchy: <ClientLayer as Layer>::Exported,
    ) -> <ClientLayer as Layer>::Exported {
        let mut map = HashMap::<_, Vec<_>>::new();
        for (vid0, records) in hierarchy {
            let old_key = old_keystore.get_key(vid0).unwrap();
            for (rid0, mut r) in records {
                let (vid1, rid1) = self.map((vid0, rid0), di);
                let new_key = new_keystore.get_key(vid1).unwrap();
                r.update_meta(old_key, rid0.into(), new_key, rid1.into()).unwrap();
                let entry = map.entry(vid1).or_default();
                entry.push((rid1, r))
            }
        }
        map
    }
}

pub struct FilterMap<T> {
    f: fn(T) -> Option<T>,
}

impl<T> Default for BidiMapping<T> {
    fn default() -> Self {
        Self { l2r: |t| t, r2l: |t| t }
    }
}
type RecordLayerMapping = BidiMapping<<RecordId as Layer>::Mapping>;
type VaultLayerMapping = BidiMapping<<VaultId as Layer>::Mapping>;
type ClientMapping = BidiMapping<<ClientId as Layer>::Mapping>;

trait Layer {
    type Id;
    type Hierarchy;
    type Exported;
    type KeyProvider;
    type Mapping;
    type MergePolicy;
}

enum SelectOne {
    KeepOld,
    Replace,
}

enum SelectOrMerge<T> {
    KeepOld,
    Replace,
    Merge(T),
}

struct VaultLayer;
impl Layer for VaultLayer {
    type Id = VaultId;
    type Hierarchy = Vec<(RecordId, BlobId)>;
    type Exported = Vec<(RecordId, Record)>;
    type KeyProvider = Key<Provider>;
    type Mapping = RecordId;
    type MergePolicy = SelectOne;
}

struct ClientLayer;
impl Layer for ClientLayer {
    type Id = ClientId;
    type Hierarchy = HashMap<VaultId, <VaultLayer as Layer>::Hierarchy>;
    type Exported = HashMap<VaultId, Vec<(RecordId, Record)>>;
    type KeyProvider = KeyStore;
    type Mapping = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;
}

trait Merge<T: Layer> {
    fn get_hierarchy(&mut self, id: T::Id) -> T::Hierarchy;

    fn get_diff(&mut self, id: T::Id, other: T::Hierarchy, merge_policy: &T::MergePolicy) -> T::Hierarchy;

    fn export_entries(&mut self, id: T::Id, hierarchy: T::Hierarchy) -> (&T::KeyProvider, T::Exported);

    fn import_entries(&mut self, id: T::Id, key_provider: &T::KeyProvider, exported: T::Exported);
}

impl Merge<VaultLayer> for SecureClient {
    fn get_hierarchy(&mut self, id: VaultId) -> Vec<(RecordId, BlobId)> {
        let key = self.keystore.get_key(id).unwrap();
        self.db.list_records_with_blob_id(key, id).unwrap()
    }

    fn get_diff(
        &mut self,
        id: VaultId,
        other: Vec<(RecordId, BlobId)>,
        merge_policy: &SelectOne,
    ) -> Vec<(RecordId, BlobId)> {
        if !self.keystore.vault_exists(id) {
            return other;
        }

        let key = self.keystore.get_key(id).unwrap();

        let mut records_diff = Vec::new();
        for (rid, blob_id) in other {
            match self.db.get_blob_id(key, id, rid) {
                Ok(bid) if bid == blob_id => {}
                Ok(_) if matches!(merge_policy, SelectOne::KeepOld) => {}
                Ok(_) | Err(VaultError::Record(RecordError::RecordNotFound(_))) | Err(VaultError::VaultNotFound(_)) => {
                    records_diff.push((rid, blob_id))
                }
                Err(VaultError::Record(_)) => todo!(),
                Err(VaultError::Procedure(_)) => unreachable!("Infallible."),
            }
        }
        records_diff
    }

    fn export_entries(
        &mut self,
        id: VaultId,
        hierarchy: Vec<(RecordId, BlobId)>,
    ) -> (&Key<Provider>, Vec<(RecordId, Record)>) {
        let key = self.keystore.get_key(id).unwrap();
        let exported = self
            .db
            .export_records(id, hierarchy.into_iter().map(|(rid, _)| rid))
            .unwrap();
        (key, exported)
    }

    fn import_entries(&mut self, id: VaultId, key: &Key<Provider>, entries: Vec<(RecordId, Record)>) {
        self.db.import_records(key, id, entries).unwrap();
    }
}

impl Merge<ClientLayer> for SecureClient {
    fn get_hierarchy(&mut self, id: ClientId) -> <ClientLayer as Layer>::Hierarchy {
        if id != self.client_id {
            todo!("return error.");
        }
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let list = <Self as Merge<VaultLayer>>::get_hierarchy(self, vid);
            map.insert(vid, list);
        }
        map
    }

    fn get_diff(
        &mut self,
        id: ClientId,
        other: <ClientLayer as Layer>::Hierarchy,
        merge_policy: &<ClientLayer as Layer>::MergePolicy,
    ) -> <ClientLayer as Layer>::Hierarchy {
        if id != self.client_id {
            todo!("return error.");
        }
        let mut diff = HashMap::new();
        for (vid, records) in other {
            match merge_policy {
                SelectOrMerge::KeepOld => {}
                SelectOrMerge::Replace => {
                    diff.insert(vid, records);
                }
                SelectOrMerge::Merge(ref p) => {
                    let records_diff = <Self as Merge<VaultLayer>>::get_diff(self, vid, records, p);
                    if !records_diff.is_empty() {
                        diff.insert(vid, records_diff);
                    }
                }
            }
        }
        diff
    }

    fn export_entries(
        &mut self,
        id: ClientId,
        hierarchy: <ClientLayer as Layer>::Hierarchy,
    ) -> (&<ClientLayer as Layer>::KeyProvider, <ClientLayer as Layer>::Exported) {
        if id != self.client_id {
            todo!("return error.");
        }

        let map = hierarchy
            .into_iter()
            .map(|(vid, entries)| (vid, <Self as Merge<VaultLayer>>::export_entries(self, vid, entries).1))
            .collect();
        (&self.keystore, map)
    }

    fn import_entries(&mut self, id: ClientId, key_store: &KeyStore, hierarchy: <ClientLayer as Layer>::Exported) {
        if id != self.client_id {
            todo!("return error.");
        }

        hierarchy.into_iter().for_each(|(vid, entries)| {
            let key = key_store.get_key(vid).unwrap();
            <Self as Merge<VaultLayer>>::import_entries(self, vid, key, entries)
        });
    }
}

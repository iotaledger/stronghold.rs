// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{RecordError, VaultError},
    state::secure::SecureClient,
};
use engine::vault::{BlobId, ClientId, RecordId, VaultId};
use std::collections::HashMap;

pub struct Mapping<T> {
    f: fn(T) -> T,
}

pub struct FilterMap<T> {
    f: fn(T) -> Option<T>,
}

impl<T> Default for Mapping<T> {
    fn default() -> Self {
        Self { f: |t| t }
    }
}
type RecordLayerMapping = Mapping<<RecordId as Layer>::Mapping>;
type VaultLayerMapping = Mapping<<VaultId as Layer>::Mapping>;
type ClientMapping = Mapping<<ClientId as Layer>::Mapping>;

trait Layer {
    type Recursion: Layer;
    type Hierarchy;
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

impl Layer for RecordId {
    type Recursion = Self;
    type Hierarchy = Vec<(Self, BlobId)>;
    type Mapping = RecordId;
    type MergePolicy = SelectOne;
}

impl Layer for VaultId {
    type Recursion = RecordId;
    type Hierarchy = HashMap<Self, <RecordId as Layer>::Hierarchy>;
    type Mapping = (VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOne>;
}

impl Layer for ClientId {
    type Recursion = VaultId;
    type Hierarchy = HashMap<Self, <VaultId as Layer>::Hierarchy>;
    type Mapping = (ClientId, VaultId, RecordId);
    type MergePolicy = SelectOrMerge<SelectOrMerge<SelectOne>>;
}

trait Merge<T: Layer> {
    fn get_hierarchy(&mut self, id: T) -> <T::Recursion as Layer>::Hierarchy;

    fn get_diff(
        &mut self,
        id: T,
        other: <T::Recursion as Layer>::Hierarchy,
        merge_policy: &<T::Recursion as Layer>::MergePolicy,
    ) -> <T::Recursion as Layer>::Hierarchy;

    fn sync_local(&mut self, source: T, target: T, filter_map: FilterMap<<T::Recursion as Layer>::Mapping>);
}

impl Merge<VaultId> for SecureClient {
    fn get_hierarchy(&mut self, id: VaultId) -> <RecordId as Layer>::Hierarchy {
        let key = self.keystore.take_key(id).unwrap();
        self.db.list_records_with_blob_id(&key, id).unwrap()
    }

    fn get_diff(
        &mut self,
        id: VaultId,
        other: <RecordId as Layer>::Hierarchy,
        merge_policy: &<RecordId as Layer>::MergePolicy,
    ) -> <RecordId as Layer>::Hierarchy {
        if !self.keystore.vault_exists(id) {
            return other;
        }

        let key = self.keystore.take_key(id).unwrap();

        let mut records_diff = Vec::new();
        for (rid, blob_id) in other {
            match self.db.get_blob_id(&key, id, rid) {
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

    fn sync_local(&mut self, source: VaultId, target: VaultId, filter_map: FilterMap<<RecordId as Layer>::Mapping>) {
        let key0 = self.keystore.take_key(source).unwrap();
        if !self.keystore.vault_exists(target) {
            let key1 = self.keystore.create_key(target);
            self.db.init_vault(key1, target);
        }
        let key1 = self.keystore.take_key(target).unwrap();
        let f = filter_map.f;
        let map_records = self
            .db
            .list_records(&source)
            .into_iter()
            .filter_map(|rid0| f(rid0).map(|rid1| (rid0, rid1)))
            .collect();
        self.db
            .copy_records_single_vault(source, &key0, target, &key1, map_records)
            .unwrap();
    }
}

impl Merge<ClientId> for SecureClient {
    fn get_hierarchy(&mut self, _id: ClientId) -> <VaultId as Layer>::Hierarchy {
        let mut map = HashMap::new();
        for vid in self.db.list_vaults() {
            let list = <Self as Merge<VaultId>>::get_hierarchy(self, vid);
            map.insert(vid, list);
        }
        map
    }

    fn get_diff(
        &mut self,
        _id: ClientId,
        other: <VaultId as Layer>::Hierarchy,
        merge_policy: &<VaultId as Layer>::MergePolicy,
    ) -> <VaultId as Layer>::Hierarchy {
        let mut diff = HashMap::new();
        for (vid, records) in other {
            match merge_policy {
                SelectOrMerge::KeepOld => {}
                SelectOrMerge::Replace => {
                    diff.insert(vid, records);
                }
                SelectOrMerge::Merge(ref p) => {
                    let records_diff = <Self as Merge<VaultId>>::get_diff(self, vid, records, p);
                    if !records_diff.is_empty() {
                        diff.insert(vid, records_diff);
                    }
                }
            }
        }
        diff
    }

    fn sync_local(
        &mut self,
        _source: ClientId,
        _target: ClientId,
        _filter_map: FilterMap<<VaultId as Layer>::Mapping>,
    ) {
        todo!("Layers don't align with implementation yet.")
    }
}

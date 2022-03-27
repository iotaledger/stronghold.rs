// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{view::Record, BlobId, ClientId, DbView, Key, RecordId, VaultId};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use crate::{Client, ClientError, ClientState, KeyStore, Provider, RecordError, VaultError};

/// Policy for conflicts when merging two vaults.
pub enum MergePolicy {
    /// Do not copy the record, instead keep the existing one.
    KeepOld,
    /// Replace the existing record.
    Replace,
}

// TODO: Use *_paths instead of `Ids`.
pub struct SyncClientsConfig {
    /// Optionally only perform a partial sync with specific vaults.
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

impl SyncClientsConfig {
    /// Selects the list of vaults that are synched in a partial sync.
    /// Each [`VaultId`] is mapped to the source's [`VaultId`] according to mapping set in
    /// [`SyncClientsConfig::map_vaults`].
    /// Returns `None` in case of a full sync.
    pub(crate) fn selected_source_vaults(&self) -> Option<Vec<VaultId>> {
        let mut vaults = self.select_vaults.clone();
        if self.map_vaults.is_empty() {
            return vaults;
        }
        if let Some(vaults) = vaults.as_mut() {
            vaults.iter_mut().for_each(|vid| {
                if let Some((&source_vid, _)) = self.map_vaults.iter().find(|(_, local_vid)| local_vid == &vid) {
                    *vid = source_vid;
                }
            })
        }
        vaults
    }

    /// Iterate through the given hierarchy from the source client. Filter out irrelevant entries
    /// if [`SyncClientsConfig::select_vaults`] or [`SyncClientsConfig::select_records`] was set.
    /// Map the source's `VaultId` to a local `VaultId`.
    pub(crate) fn filter_map<T>(
        &self,
        hierarchy: HashMap<VaultId, Vec<(RecordId, T)>>,
    ) -> HashMap<VaultId, Vec<(RecordId, T)>> {
        if self.select_vaults.is_none() && self.select_records.is_empty() && self.map_vaults.is_empty() {
            return hierarchy;
        }
        hierarchy
            .into_iter()
            .filter_map(|(vid, mut records)| {
                let vid = self.map_vaults.get(&vid).copied().unwrap_or(vid);
                if let Some(select_vaults) = self.select_vaults.as_ref() {
                    if !select_vaults.contains(&vid) {
                        return None;
                    }
                }
                if let Some(select_records) = self.select_records.get(&vid) {
                    records.retain(|(rid, _)| select_records.contains(rid));
                }
                Some((vid, records))
            })
            .collect()
    }
}

/// Immutable access to a client's [`DbView`] and [`KeyStore`].
pub struct ClientRef<DB, KS>
where
    DB: Deref<Target = DbView<Provider>>,
    KS: Deref<Target = KeyStore<Provider>>,
{
    pub db: DB,
    pub keystore: KS,
}

impl<DB, KS> ClientRef<DB, KS>
where
    DB: Deref<Target = DbView<Provider>>,
    KS: Deref<Target = KeyStore<Provider>>,
{
    pub fn get_hierarchy(&self, vaults: Option<Vec<VaultId>>) -> HashMap<VaultId, Vec<(RecordId, BlobId)>> {
        let vaults = vaults.unwrap_or_else(|| self.db.list_vaults());
        vaults
            .into_iter()
            .map(|vid| {
                let key = self.keystore.get_key(vid).unwrap();
                let list = self.db.list_records_with_blob_id(&key, vid).unwrap();
                (vid, list)
            })
            .collect()
    }

    pub fn get_diff(
        &self,
        other: HashMap<VaultId, Vec<(RecordId, BlobId)>>,
        merge_policy: &MergePolicy,
    ) -> HashMap<VaultId, Vec<RecordId>> {
        other
            .into_iter()
            .map(|(vid, list)| {
                let target_key = self.keystore.get_key(vid).unwrap();
                let diff = list
                    .into_iter()
                    .filter_map(|(rid, bid)| {
                        if !self.db.contains_record(vid, rid) {
                            return Some(rid);
                        }
                        if matches!(merge_policy, MergePolicy::KeepOld) {
                            return None;
                        }
                        if self.db.get_blob_id(&target_key, vid, rid).unwrap() == bid {
                            return None;
                        }
                        Some(rid)
                    })
                    .collect();
                (vid, diff)
            })
            .collect()
    }

    pub fn export_entries(&self, select: HashMap<VaultId, Vec<RecordId>>) -> HashMap<VaultId, Vec<(RecordId, Record)>> {
        select
            .into_iter()
            .map(|(vid, select)| (vid, self.db.export_records(vid, select).unwrap()))
            .collect()
    }
}

impl<'a> From<&'a ClientState> for ClientRef<&'a DbView<Provider>, &'a KeyStore<Provider>> {
    fn from(state: &'a ClientState) -> Self {
        ClientRef {
            db: &state.1,
            keystore: todo!(),
        }
    }
}

impl<'a> TryFrom<&'a Client>
    for ClientRef<RwLockReadGuard<'a, DbView<Provider>>, RwLockReadGuard<'a, KeyStore<Provider>>>
{
    type Error = ClientError;

    fn try_from(client: &'a Client) -> Result<Self, Self::Error> {
        let db = client.db.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let keystore = client.keystore.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let state = ClientRef { db, keystore };
        Ok(state)
    }
}

/// Mutable access to a client's [`DbView`] and [`KeyStore`].
pub struct ClientRefMut<DB, KS>
where
    DB: DerefMut<Target = DbView<Provider>>,
    KS: Deref<Target = KeyStore<Provider>>,
{
    pub db: DB,
    pub keystore: KS,
}

impl<DB, KS> ClientRefMut<DB, KS>
where
    DB: DerefMut<Target = DbView<Provider>>,
    KS: Deref<Target = KeyStore<Provider>>,
{
    pub fn import_own_records(
        &mut self,
        records: HashMap<VaultId, Vec<(RecordId, Record)>>,
        mapping: HashMap<VaultId, VaultId>,
    ) {
        for (vid, records) in records {
            let old_vid = mapping.get(&vid).copied().unwrap_or(vid);
            let old_key = self.keystore.get_key(old_vid).unwrap();
            let new_key = self.keystore.get_key(vid).unwrap();
            self.db.import_records(&old_key, &new_key, vid, records).unwrap()
        }
    }

    pub fn import_records(
        &mut self,
        records: HashMap<VaultId, Vec<(RecordId, Record)>>,
        old_keystore: &KS,
        mapping: HashMap<VaultId, VaultId>,
    ) {
        for (vid, records) in records {
            let old_vid = mapping.get(&vid).copied().unwrap_or(vid);
            let old_key = old_keystore.get_key(old_vid).unwrap();
            let new_key = self.keystore.get_key(vid).unwrap();
            self.db.import_records(&old_key, &new_key, vid, records).unwrap()
        }
    }
}

impl<'a> TryFrom<&'a Client>
    for ClientRefMut<RwLockWriteGuard<'a, DbView<Provider>>, RwLockReadGuard<'a, KeyStore<Provider>>>
{
    type Error = ClientError;

    fn try_from(client: &'a Client) -> Result<Self, Self::Error> {
        let db = client.db.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        let keystore = client.keystore.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let state = ClientRefMut { db, keystore };
        Ok(state)
    }
}

impl<'a> From<&'a mut ClientState> for ClientRefMut<&'a mut DbView<Provider>, &'a KeyStore<Provider>> {
    fn from(state: &'a mut ClientState) -> Self {
        ClientRefMut {
            db: &mut state.1,
            keystore: todo!(),
        }
    }
}

pub struct SyncSnapshotsConfig {
    pub select_clients: Option<Vec<ClientId>>,
    pub select_vaults: HashMap<ClientId, Vec<VaultId>>,
    pub select_records: HashMap<(ClientId, VaultId), Vec<RecordId>>,
    pub map_clients: HashMap<ClientId, ClientId>,
    pub map_vaults: HashMap<(ClientId, VaultId), VaultId>,
    pub merge_policy: MergePolicy,
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     use crate::{procedures::Runner, state::secure::SecureClient, Location};
//     use engine::vault::RecordHint;
//     use stronghold_utils::random;

//     fn test_hint() -> RecordHint {
//         random::random::<[u8; 24]>().into()
//     }

//     fn test_value() -> Vec<u8> {
//         random::bytestring(4096)
//     }

//     fn test_location() -> Location {
//         let v_path = random::bytestring(4096);
//         let r_path = random::bytestring(4096);
//         Location::generic(v_path, r_path)
//     }

//     fn vault_path_to_id(path: &str) -> VaultId {
//         SecureClient::derive_vault_id(path.as_bytes().to_vec())
//     }

//     fn r_ctr_to_id(vault_path: &str, ctr: usize) -> RecordId {
//         SecureClient::derive_record_id(vault_path.as_bytes().to_vec(), ctr)
//     }

//     fn perform_sync(
//         source: &mut SyncClientState,
//         target: &mut SyncClientState,
//         mapper: Option<&Mapper<(VaultId, RecordId)>>,
//         merge_policy: SelectOrMerge<SelectOne>,
//     ) -> Result<(), VaultError> {
//         let hierarchy = source.get_hierarchy()?;
//         let diff = target.get_diff(hierarchy, mapper, &merge_policy)?;
//         let exported = source.export_entries(Some(diff))?;
//         target.import_entries(exported, &merge_policy, mapper, Some(&*source.keystore))?;
//         Ok(())
//     }

//     #[test]
//     fn test_get_hierarchy() -> Result<(), Box<dyn std::error::Error>> {
//         let cid = ClientId::random::<Provider>()?;
//         let mut client = SecureClient::new(cid);
//         let hierarchy = SyncClientState::from(&mut client).get_hierarchy()?;
//         assert!(hierarchy.is_empty());

//         let location_1 = test_location();
//         let (vid1, rid1) = SecureClient::resolve_location(location_1.clone());
//         client.write_to_vault(&location_1, test_hint(), test_value())?;

//         let v_path_2 = random::bytestring(4096);
//         let r_path_2 = random::bytestring(4096);
//         let location_2 = Location::generic(v_path_2.clone(), r_path_2);
//         let (vid2, rid2) = SecureClient::resolve_location(location_2.clone());
//         client.write_to_vault(&location_2, test_hint(), test_value())?;

//         // Same vault as value nr 2.
//         let r_path_3 = random::bytestring(4096);
//         let location_3 = Location::generic(v_path_2, r_path_3);
//         let (vid23, rid3) = SecureClient::resolve_location(location_3.clone());
//         assert_eq!(vid2, vid23);
//         client.write_to_vault(&location_3, test_hint(), test_value())?;

//         let hierarchy = SyncClientState::from(&mut client).get_hierarchy()?;

//         assert_eq!(hierarchy.len(), 2);
//         let records_1 = hierarchy
//             .iter()
//             .find(|(k, _)| **k == vid1)
//             .expect("Vault does not exist.")
//             .1;
//         assert_eq!(records_1.len(), 1);
//         assert_eq!(records_1[0].0, rid1);

//         let records_2 = hierarchy
//             .iter()
//             .find(|(k, _)| **k == vid2)
//             .expect("Vault does not exist.")
//             .1;
//         assert_eq!(records_2.len(), 2);
//         assert!(records_2.iter().any(|(rid, _)| rid == &rid2));
//         assert!(records_2.iter().any(|(rid, _)| rid == &rid3));

//         Ok(())
//     }

//     #[test]
//     fn test_export_with_mapping() -> Result<(), Box<dyn std::error::Error>> {
//         let mapping = |(vid, rid)| {
//             if vid == vault_path_to_id("vault_1") {
//                 if rid == r_ctr_to_id("vault_1", 11) {
//                     // Map record in same vault to new record id.
//                     Some((vid, r_ctr_to_id("vault_1", 111)))
//                 } else if rid == r_ctr_to_id("vault_1", 12) {
//                     // Map record to a vault that we skipped in the sources hierarchy.
//                     Some((vault_path_to_id("vault_3"), r_ctr_to_id("vault_3", 121)))
//                 } else if rid == r_ctr_to_id("vault_1", 13) {
//                     // Map record to an entirely new vault.
//                     Some((vault_path_to_id("vault_4"), r_ctr_to_id("vault_4", 13)))
//                 } else {
//                     // Keep at same location.
//                     Some((vid, rid))
//                 }
//             } else if vid == vault_path_to_id("vault_2") {
//                 // Move whole vault.
//                 Some((vault_path_to_id("vault_5"), rid))
//             } else {
//                 // Skip record from any source vault with path != vault_1 || vault_2.
//                 None
//             }
//         };
//         let mapper = Mapper { f: mapping };

//         let cid0 = ClientId::random::<Provider>()?;
//         let mut source_client = SecureClient::new(cid0);

//         // Fill test vaults.
//         for i in 1..4usize {
//             for j in 1..5usize {
//                 let vault_path = format!("vault_{}", i);
//                 let location = Location::counter(vault_path, i * 10 + j);
//                 source_client.write_to_vault(&location, test_hint(), test_value())?;
//             }
//         }

//         let mut target_client = SecureClient::new(cid0);

//         let mut source = SyncClientState::from(&mut source_client);
//         let mut target = SyncClientState::from(&mut target_client);
//         let merge_policy = match random::random::<u8>() % 4 {
//             0 => SelectOrMerge::KeepOld,
//             1 => SelectOrMerge::Replace,
//             2 => SelectOrMerge::Merge(SelectOne::KeepOld),
//             3 => SelectOrMerge::Merge(SelectOne::Replace),
//             _ => unreachable!("0 <= n % 4 <= 3"),
//         };

//         let source_hierarchy = source.get_hierarchy()?;
//         let target_hierarchy = target.get_hierarchy()?;
//         assert!(target_hierarchy.is_empty());

//         // Do sync.
//         perform_sync(&mut source, &mut target, Some(&mapper), merge_policy)?;

//         // Check that old state still contains all values
//         let check_hierarchy = source.get_hierarchy()?;
//         assert_eq!(source_hierarchy, check_hierarchy);

//         let mut target_hierarchy = target.get_hierarchy()?;
//         assert_eq!(target_hierarchy.keys().len(), 4);

//         // Vault-1 was partly mapped.
//         let v_1_entries = target_hierarchy
//             .remove(&vault_path_to_id("vault_1"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_1_entries.len(), 2);
//         // Record-14 was not moved.
//         assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 14)));
//         // Record-11 was moved to counter 111.
//         assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 111)));

//         // All records from Vault-2 were moved to Vault-5.
//         assert!(!target_hierarchy.contains_key(&vault_path_to_id("vault_2")));
//         let v_5_entries = target_hierarchy
//             .remove(&vault_path_to_id("vault_5"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_5_entries.len(), 4);
//         assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
//         assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)));
//         assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
//         assert!(v_5_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 24)));

//         // Vault-3 from source was skipped, but Record-12 from Vault-1 was moved to Vault-3 Record-121.
//         let v_3_entries = target_hierarchy
//             .remove(&vault_path_to_id("vault_3"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_3_entries.len(), 1);
//         assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 121)));

//         // Record-13 from Vault-1 was moved to new Vault-4.
//         let v_4_entries = target_hierarchy
//             .remove(&vault_path_to_id("vault_4"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_4_entries.len(), 1);
//         assert!(v_4_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_4", 13)));

//         Ok(())
//     }

//     #[test]
//     fn test_merge_policy() -> Result<(), Box<dyn std::error::Error>> {
//         let cid0 = ClientId::random::<Provider>()?;
//         let mut source_client = SecureClient::new(cid0);

//         // Fill test vaults.
//         for i in 1..3usize {
//             for j in 1..3usize {
//                 let vault_path = format!("vault_{}", i);
//                 let location = Location::counter(vault_path, i * 10 + j);
//                 source_client.write_to_vault(&location, test_hint(), test_value())?;
//             }
//         }

//         let mut source = SyncClientState::from(&mut source_client);
//         let mut source_vault_2_hierarchy = source
//             .get_hierarchy()?
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         source_vault_2_hierarchy.sort();
//         let source_v2_r2_bid = source_vault_2_hierarchy
//             .iter()
//             .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
//             .map(|(_, bid)| *bid)
//             .expect("Record does not exist.");

//         let set_up_target = || -> Result<SecureClient, VaultError> {
//             let mut target_client = SecureClient::new(cid0);
//             for i in 2..4usize {
//                 for j in 2..4usize {
//                     let vault_path = format!("vault_{}", i);
//                     let location = Location::counter(vault_path, i * 10 + j);
//                     target_client.write_to_vault(&location, test_hint(), test_value())?;
//                 }
//             }
//             Ok(target_client)
//         };

//         let assert_for_distinct_vaults = |hierarchy: &mut HashMap<VaultId, Vec<(RecordId, BlobId)>>| {
//             // Imported full vault-1;
//             assert_eq!(hierarchy.keys().len(), 3);
//             let v_1_entries = hierarchy
//                 .remove(&vault_path_to_id("vault_1"))
//                 .expect("Vault does not exist.");
//             assert_eq!(v_1_entries.len(), 2);
//             assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 11)));
//             assert!(v_1_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_1", 12)));

//             // Kept old vault-3;
//             let v_3_entries = hierarchy
//                 .remove(&vault_path_to_id("vault_3"))
//                 .expect("Vault does not exist.");
//             assert_eq!(v_3_entries.len(), 2);
//             assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 32)));
//             assert!(v_3_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_3", 33)));
//         };

//         // == Test merge policy SelectOrMerge::KeepOld

//         let mut target_client_1 = set_up_target()?;
//         let mut target_1 = SyncClientState::from(&mut target_client_1);
//         let mut old_vault_2_hierarchy = target_1
//             .get_hierarchy()?
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         old_vault_2_hierarchy.sort();
//         let merge_policy = SelectOrMerge::KeepOld;

//         perform_sync(&mut source, &mut target_1, None, merge_policy)?;

//         let mut hierarchy_1 = target_1.get_hierarchy()?;

//         assert_for_distinct_vaults(&mut hierarchy_1);

//         // Kept old vault-2.
//         let mut v_2_entries = hierarchy_1
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         v_2_entries.sort();
//         assert_eq!(v_2_entries, old_vault_2_hierarchy);

//         // == Test merge policy SelectOrMerge::Replace

//         let mut target_client_2 = set_up_target()?;
//         let mut target_2 = SyncClientState::from(&mut target_client_2);
//         let merge_policy = SelectOrMerge::Replace;
//         perform_sync(&mut source, &mut target_2, None, merge_policy)?;
//         let mut hierarchy_2 = target_2.get_hierarchy()?;

//         assert_for_distinct_vaults(&mut hierarchy_2);

//         // Replace vault-2 completely with imported one;
//         let mut v_2_entries = hierarchy_2
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         v_2_entries.sort();
//         assert_eq!(v_2_entries, source_vault_2_hierarchy);

//         // == Test merge policy SelectOrMerge::Merge(SelectOne::KeepOld)

//         let mut target_client_3 = set_up_target()?;
//         let mut target_3 = SyncClientState::from(&mut target_client_3);
//         let old_v2_r2_bid = target_3
//             .get_hierarchy()?
//             .remove(&vault_path_to_id("vault_2"))
//             .and_then(|vec| vec.into_iter().find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22)))
//             .map(|(_, bid)| bid)
//             .expect("Record does not exist.");
//         let merge_policy = SelectOrMerge::Merge(SelectOne::KeepOld);
//         perform_sync(&mut source, &mut target_3, None, merge_policy)?;
//         let mut hierarchy_3 = target_3.get_hierarchy()?;

//         assert_for_distinct_vaults(&mut hierarchy_3);

//         // Merge vault-2 with imported one, keep old record on conflict.
//         let v_2_entries = hierarchy_3
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_2_entries.len(), 3);
//         assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
//         assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
//         let v2_r2_bid = v_2_entries
//             .into_iter()
//             .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
//             .map(|(_, bid)| bid)
//             .expect("Record does not exist.");
//         assert_eq!(v2_r2_bid, old_v2_r2_bid);

//         // == Test merge policy SelectOrMerge::Merge(SelectOne::Replace)

//         let mut target_client_4 = set_up_target()?;
//         let mut target_4 = SyncClientState::from(&mut target_client_4);
//         let merge_policy = SelectOrMerge::Merge(SelectOne::Replace);
//         perform_sync(&mut source, &mut target_4, None, merge_policy)?;
//         let mut hierarchy_4 = target_4.get_hierarchy()?;

//         assert_for_distinct_vaults(&mut hierarchy_4);

//         // Merge vault-2 with imported one, keep old record on conflict.
//         let v_2_entries = hierarchy_4
//             .remove(&vault_path_to_id("vault_2"))
//             .expect("Vault does not exist.");
//         assert_eq!(v_2_entries.len(), 3);
//         assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 21)));
//         assert!(v_2_entries.iter().any(|(rid, _)| rid == &r_ctr_to_id("vault_2", 23)));
//         let v2_r2_bid = v_2_entries
//             .into_iter()
//             .find(|(rid, _)| rid == &r_ctr_to_id("vault_2", 22))
//             .map(|(_, bid)| bid)
//             .expect("Record does not exist.");
//         assert_eq!(v2_r2_bid, source_v2_r2_bid);

//         Ok(())
//     }
// }

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity, unused_imports)]

use actix::{Actor, Handler, Message, Supervised};
use zeroize::Zeroize;

use std::{
    convert::TryInto,
    hash::{Hash, Hasher},
    io::Read,
    path::PathBuf,
};

use engine::{
    snapshot::Key,
    vault::{ClientId, DbView, Key as PKey, RecordId, VaultError, VaultId},
};

use serde::{Deserialize, Serialize};

use crate::{
    internals,
    state::{
        secure::Store,
        snapshot::{ReadError, Snapshot, SnapshotState, WriteError},
    },
    utils::EntryShape,
    Location, Provider,
};
use std::collections::HashMap;

/// re-export local modules
pub use messages::*;
pub use returntypes::*;

pub mod returntypes {

    use engine::vault::Key;

    use super::*;

    /// Return type for loaded snapshot file
    pub struct ReturnReadSnapshot {
        pub id: ClientId,

        pub data: Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>,
    }

    /// Return type for snapshot data exports
    pub struct ReturnExport {
        pub entries: Vec<u8>,
    }
}

pub mod messages {

    use zeroize::Zeroize;

    use crate::Location;

    use super::*;

    pub struct WriteSnapshot {
        pub key: Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
    }

    impl Message for WriteSnapshot {
        type Result = Result<(), WriteError>;
    }

    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = ();
    }

    #[derive(Default)]
    pub struct ReadFromSnapshot {
        pub key: Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub id: ClientId,
        pub fid: Option<ClientId>,
    }

    impl Message for ReadFromSnapshot {
        type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;
    }

    /// Message for [`Snapshot`] to create a partially synchronized snapshot.
    /// A partially synchronized snapshot contains only the associated data like
    /// vaults and their records, that is related to specified [`ClientId`]s
    /// and their associated keys.
    #[derive(Clone)]
    pub struct PartialSynchronization {
        // this passes a list of all allowed client_ids
        // to be synchronized
        pub allowed: Vec<ClientId>,

        // this snapshot file will be used as base snapshot
        pub source: SnapshotConfig,

        // this snapshot file will be used to compare against
        // the source snapshot
        pub compare: SnapshotConfig,

        // this is the destination snapshot to written out
        pub destination: SnapshotConfig,

        // the id of the client
        pub id: ClientId,
    }

    impl Message for PartialSynchronization {
        type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;
    }

    /// Message for [`Snapshot`] to create a fully synchronized snapshot.
    /// A fully synchronized snapshot contains all [`ClientId`]s, and
    /// all associated data like vaults and their records.
    #[derive(Clone)]
    pub struct FullSynchronization {
        // this snapshot file will be used as base snapshot
        pub source: SnapshotConfig,

        // this is the snapshot to synchronized with the current state
        pub merge: SnapshotConfig,

        // this is the destination snapshot
        pub destination: SnapshotConfig,

        // the id of the client
        pub id: ClientId,
    }

    impl Message for FullSynchronization {
        type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;
    }

    /// Exports all entries given their prior keys, and re-encrypted
    /// via the new keys. Part of the snapshot protocol.
    pub struct ExportAllEntries {
        // pub entries: HashMap<Location, (PKey<Provider>, PKey<Provider>)>,
        // we only need the location
        pub entries: Vec<Location>,
        // pub state: HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>,
    }

    impl Message for ExportAllEntries {
        type Result = Result<(HashMap<VaultId, PKey<Provider>>, DbView<Provider>), ReadError>;
    }

    /// Exports the complete snapshot as vector of bytes. Part of the snapshot protocol
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExportSnapshot {
        pub id: ClientId,
        pub input: Vec<Location>,
        pub public_key: Vec<u8>,
    }

    impl Message for ExportSnapshot {
        type Result = Result<Vec<u8>, ReadError>;
    }

    /// Returns a representation of the selected locations and their shape.
    /// Part of the snapshot protocol
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CalculateShape {
        pub id: ClientId,
    }

    impl Message for CalculateShape {
        type Result = Result<HashMap<(VaultId, RecordId), EntryShape>, ReadError>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CalculateComplement {
        pub input: HashMap<Location, EntryShape>,
        pub id: ClientId,
    }

    impl Message for CalculateComplement {
        type Result = Result<HashMap<(VaultId, RecordId), EntryShape>, ReadError>;
    }

    /// Returns the complement set of the side to be synchronized with. Part of the snapshot protocol
    pub struct ExportComplement {
        pub input: HashMap<Location, EntryShape>,
        pub key: Key,
        pub id: ClientId,
    }

    impl Message for ExportComplement {
        type Result = Result<Vec<u8>, WriteError>;
    }

    pub struct SerializeSnapshot {
        pub input: HashMap<Location, EntryShape>,
        pub key: Key,
        pub id: ClientId,
    }

    impl Message for SerializeSnapshot {
        type Result = Result<Vec<u8>, WriteError>;
    }

    pub struct DeserializeSnapshot {
        pub input: Vec<u8>,
        pub key: Vec<u8>,
    }

    impl Message for DeserializeSnapshot {
        type Result =
            Result<Box<HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>>, ReadError>;
    }

    pub struct UnpackSnapshotData {
        /// Contains the serialize snapshot with a virtual [`ClientId`]
        pub data: Vec<u8>,

        /// The key to decrypt the snapshot data
        pub key: Vec<u8>,
    }

    impl Message for UnpackSnapshotData {
        type Result = Result<
            Box<(
                HashMap<VaultId, PKey<internals::Provider>>,
                DbView<internals::Provider>,
                Store,
            )>,
            ReadError,
        >;
    }
}

/// This struct provide file system configuration to the messages ['FullSynchronization`]
/// and [`PartialSynchronization`] it optionally expects a `path` or a `filename`, either
/// the stronghold snapshot resides at another place than the default, or the latter, if
/// the name of the snapshot is known.
/// TODO: move to types(?)
#[derive(Clone)]
pub struct SnapshotConfig {
    // the filename of the snapshot file in the default snapshot directory
    pub filename: Option<String>,

    // the path to the snapshot file, if it is not inside the default folder
    pub path: Option<PathBuf>,

    // the key to encrypt / decrypt the snapshot file
    pub key: Key,

    // set this to `true` will generate the written output as slice of bytes
    pub generates_output: bool,
}

impl Supervised for Snapshot {}
impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::FillSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.state.add_data(msg.id, *msg.data);
    }
}

impl Handler<messages::ReadFromSnapshot> for Snapshot {
    type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;

    /// This will try to read from a snapshot on disk, otherwise load from a local snapshot
    /// in memory. Returns the loaded snapshot data, that must be loaded inside the client
    /// for access.
    fn handle(&mut self, msg: messages::ReadFromSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        let id = msg.fid.unwrap_or(msg.id);

        if self.has_data(id) {
            let data = self.get_state(id);

            Ok(ReturnReadSnapshot {
                id,
                data: Box::new(data),
            })
        } else {
            let mut snapshot = Snapshot::read_from_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;
            let data = snapshot.get_state(id);
            *self = snapshot;

            Ok(ReturnReadSnapshot {
                id,
                data: Box::new(data),
            })
        }
    }
}

impl Handler<messages::WriteSnapshot> for Snapshot {
    type Result = Result<(), WriteError>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;

        self.state = SnapshotState::default();

        Ok(())
    }
}

// --- synchronization handlers

impl Handler<UnpackSnapshotData> for Snapshot {
    type Result = Result<
        Box<(
            HashMap<VaultId, PKey<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>,
        ReadError,
    >;

    #[allow(unused_variables)]
    fn handle(&mut self, msg: UnpackSnapshotData, ctx: &mut Self::Context) -> Self::Result {
        // todo: move the virtual client_id to top as constant
        let client_id_virtual = ClientId::load(b"virtual-import-synchronization").unwrap();

        match <Self as Handler<DeserializeSnapshot>>::handle(
            self,
            DeserializeSnapshot {
                input: msg.data,
                key: msg.key,
            },
            ctx,
        ) {
            Ok(mut result) => match result.remove(&client_id_virtual) {
                Some(to_boxed) => Ok(Box::new(to_boxed)),
                None => Err(ReadError::InvalidFile("No data for Clientid present".to_string())),
            },
            Err(error) => Err(error),
        }
    }
}

impl Handler<messages::CalculateComplement> for Snapshot {
    type Result = Result<HashMap<(VaultId, RecordId), EntryShape>, ReadError>;

    #[allow(unused_variables)]
    fn handle(&mut self, msg: messages::CalculateComplement, ctx: &mut Self::Context) -> Self::Result {
        let output = HashMap::new();

        let local_shapes = match <Self as Handler<CalculateShape>>::handle(self, CalculateShape { id: msg.id }, ctx) {
            Ok(shapes) => shapes,
            Err(error) => return Err(error),
        };

        for (a, b) in msg.input.iter() {
            // let vid_remote = a.try_into();
        }

        Ok(output)
    }
}

impl Handler<messages::SerializeSnapshot> for Snapshot {
    type Result = Result<Vec<u8>, WriteError>;

    #[allow(unused_variables)]
    fn handle(&mut self, msg: messages::SerializeSnapshot, ctx: &mut Self::Context) -> Self::Result {
        todo!()
    }
}

// snapshot synchronisation protocol
impl Handler<messages::ExportAllEntries> for Snapshot {
    type Result = Result<(HashMap<VaultId, PKey<Provider>>, DbView<Provider>), ReadError>;

    fn handle(&mut self, message: messages::ExportAllEntries, _ctx: &mut Self::Context) -> Self::Result {
        let mut result_view: DbView<Provider> = DbView::new();
        let mut result_map = HashMap::new();

        // access inner
        let inner = &mut self.state.0;

        // iterate over all client ids, and select entries
        for (_id, (keys, view, _)) in inner.iter_mut() {
            // let view = &mut data.1;

            for location in message.entries.iter() {
                let vid: VaultId = location.try_into().unwrap();
                let rid: RecordId = location.try_into().unwrap();

                let key = keys.get(&vid).unwrap(); // can potentially fail

                if !view.contains_record(key, vid, rid) {
                    continue;
                }

                let id_hint = crate::utils::into_map(view.list_hints_and_ids(key, vid));

                // decrypt entry and re-encrypt with new key inside guard
                view.get_guard(key, vid, rid, |guarded_data| {
                    let record_hint = id_hint
                        .get(&rid)
                        .ok_or_else(|| ReadError::InvalidFile("No RecordHint Present".to_string()))?;

                    result_view
                        .write(key, vid, rid, &guarded_data.borrow(), *record_hint)
                        .map_err(|error| ReadError::InvalidFile(error.to_string()))?;
                    result_map.insert(vid, key.clone());

                    Ok(())
                })
                .map_err(|error: VaultError<_, ReadError>| ReadError::InvalidFile(error.to_string()))?;
            }
        }

        Ok((result_map, result_view))
    }
}
// snapshot synchronisation protocol
impl Handler<messages::ExportSnapshot> for Snapshot {
    type Result = Result<Vec<u8>, ReadError>;

    fn handle(&mut self, message: messages::ExportSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        // (1) create empty map, view, and store
        // (2) export the given locations
        // (3) write the given locations into empty containers
        // (4) embed containers into snapshot, serialize it and return the bytes

        // internal result
        let mut result_view = DbView::new();
        let mut result_maps = HashMap::new();

        // access inner
        let inner = &mut self.state.0;

        // queue
        let mut queue = Vec::new();
        queue.clone_from(&message.input);

        // iterate over all client ids, and select entries
        'entries: for (_id, (keys, vault, _)) in inner.iter_mut() {
            // let vault = &mut data.1;

            'comparison: loop {
                if let Some(ref location) = queue.pop() {
                    let vid: VaultId = location.try_into().unwrap();
                    let rid: RecordId = location.try_into().unwrap();

                    let key = keys.get(&vid).unwrap();

                    if vault.contains_record(key, vid, rid) {
                        let id_hint = crate::utils::into_map(vault.list_hints_and_ids(key, vid));

                        vault
                            .get_guard(key, vid, rid, |guarded_data| {
                                let record_hint = id_hint
                                    .get(&rid)
                                    .ok_or_else(|| ReadError::InvalidFile("No RecordHint Present".to_string()))?;

                                // this will reuse the old key
                                result_view
                                    .write(key, vid, rid, &guarded_data.borrow(), *record_hint)
                                    .map_err(|error| ReadError::InvalidFile(error.to_string()))?;
                                result_maps.insert(vid, key.clone());

                                Ok(())
                            })
                            .map_err(|error: VaultError<_, ReadError>| ReadError::InvalidFile(error.to_string()))?;

                        // process next entry
                        continue;
                    }

                    break 'comparison;
                }

                // nothing more to process, skip outer loop
                break 'entries;
            }
        }

        // create new snapshot by serializing the state
        let state = SnapshotState::new(message.id, (result_maps, result_view, Store::default()));

        // serialize and return
        state
            .serialize()
            .map_err(|error| ReadError::CorruptedContent(error.to_string()))
    }
}

/// returns the complentary set of entries
impl Handler<messages::ExportComplement> for Snapshot {
    type Result = Result<Vec<u8>, WriteError>;

    #[allow(unused_variables)]
    fn handle(&mut self, message: messages::ExportComplement, ctx: &mut Self::Context) -> Self::Result {
        // (1) calc shape internally
        let shape_internal =
            <Self as Handler<messages::CalculateShape>>::handle(self, CalculateShape { id: message.id }, ctx);

        // (2) calculate complement internally
        let complement = <Self as Handler<messages::CalculateComplement>>::handle(
            self,
            CalculateComplement {
                input: message.input.clone(),
                id: message.id,
            },
            ctx,
        );

        // (3) create snapshot with provided key and return
        <Self as Handler<messages::SerializeSnapshot>>::handle(
            self,
            SerializeSnapshot {
                id: message.id,
                input: message.input,
                key: message.key,
            },
            ctx,
        )
    }
}

// snapshot synchronisation protocol
impl Handler<messages::CalculateShape> for Snapshot {
    type Result = Result<HashMap<(VaultId, RecordId), EntryShape>, ReadError>;

    #[allow(unused_variables)]
    fn handle(&mut self, message: messages::CalculateShape, _ctx: &mut Self::Context) -> Self::Result {
        let inner = &mut self.state.0;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let mut output = HashMap::new();

        inner.iter_mut().for_each(|(_, (vaultkeys, view, store))| {
            vaultkeys.iter().for_each(|(vid, key)| {
                view.list_hints_and_ids(key, *vid).iter().for_each(|(rid, _)| {
                    view.get_guard::<String, _>(key, *vid, *rid, |guard| {
                        let data = guard.borrow();

                        data.hash(&mut hasher);

                        // create EntryShape
                        let entry_shape = EntryShape {
                            vid: *vid,
                            rid: *rid,
                            record_hash: hasher.finish(),
                            record_size: data.len(),
                        };

                        // and store it in output
                        output.insert((*vid, *rid), entry_shape);

                        Ok(())
                    })
                    .unwrap();
                })
            });
        });

        Ok(output)
    }
}

impl Handler<DeserializeSnapshot> for Snapshot {
    type Result =
        Result<Box<HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>>, ReadError>;

    fn handle(&mut self, msg: DeserializeSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        let mut key = [0u8; 32];
        key.clone_from_slice(&msg.key);

        match Snapshot::read_from_data(msg.input, key, None) {
            Ok(snapshot) => Ok(Box::from(snapshot.state.0)),
            Err(error) => Err(error),
        }
    }
}

impl Handler<messages::FullSynchronization> for Snapshot {
    type Result = Result<ReturnReadSnapshot, ReadError>;

    fn handle(&mut self, msg: messages::FullSynchronization, ctx: &mut Self::Context) -> Self::Result {
        let merge_config = msg.merge;
        let snapshot_data_merge = Snapshot::read_from_name_or_path(
            merge_config.filename.as_deref(),
            merge_config.path.as_deref(),
            merge_config.key,
        )?;

        let local_config = msg.source;
        let snapshot_data_local = Snapshot::read_from_name_or_path(
            local_config.filename.as_deref(),
            local_config.path.as_deref(),
            local_config.key,
        )?;

        let dst_config = msg.destination;

        let snapshot_local = bincode::deserialize::<SnapshotState>(&snapshot_data_local)
            .map_err(|error| ReadError::InvalidFile(error.to_string()))?;

        // merge this state into current state
        let snapshot_merge = bincode::deserialize::<SnapshotState>(&snapshot_data_merge)
            .map_err(|error| ReadError::InvalidFile(error.to_string()))?;

        // this is the actual output of the handler
        let mut output_map: HashMap<VaultId, PKey<Provider>> = HashMap::new();
        let mut output_view: DbView<Provider> = DbView::new();
        let mut output_store: Store = Store::new();

        let mut output_state = SnapshotState::default();

        // copy all merge
        for id in snapshot_merge.0.keys() {
            if let Some(data) = snapshot_merge.0.get(&id.clone()) {
                output_state.add_data(*id, data.clone());

                let (map, view, store) = data;
                output_map.extend((map.clone()).into_iter());

                // changed api
                output_store.merge(store.clone());
                output_view.vaults.extend(view.vaults.clone().into_iter());
            }
        }

        // copy all local
        for id in snapshot_local.0.keys() {
            if let Some(data) = snapshot_local.0.get(&id.clone()) {
                output_state.add_data(*id, data.clone());

                let (map, view, store) = data;
                output_map.extend((map.clone()).into_iter());
                output_view.vaults.extend(view.vaults.clone().into_iter());

                // changed api
                output_store.merge(store.clone());
            }
        }

        self.state = output_state;

        let write_msg = WriteSnapshot {
            key: dst_config.key,
            filename: dst_config.filename,
            path: dst_config.path,
        };

        // write the new state to disk
        <Self as Handler<WriteSnapshot>>::handle(self, write_msg, ctx)
            .map_err(|error| ReadError::InvalidFile(error.to_string()))?;

        // return read state to reload on current actor
        Ok(ReturnReadSnapshot {
            id: msg.id,
            data: Box::new((output_map, output_view, output_store)),
        })
    }
}

impl Handler<messages::PartialSynchronization> for Snapshot {
    type Result = Result<ReturnReadSnapshot, ReadError>;

    fn handle(&mut self, msg: messages::PartialSynchronization, ctx: &mut Self::Context) -> Self::Result {
        // load associated system snapshot
        let src_config = msg.source;
        let snapshot_data_source = Snapshot::read_from_name_or_path(
            src_config.filename.as_deref(),
            src_config.path.as_deref(),
            src_config.key,
        )?;

        // load snapshot file for comparison
        // FIXME: this should be the current state of the secure actor
        let cmp_config = msg.compare;
        let snapshot_data_compare = Snapshot::read_from_name_or_path(
            cmp_config.filename.as_deref(),
            cmp_config.path.as_deref(),
            cmp_config.key,
        )?;

        // set snapshot file to be synchronized with
        let dst_config = msg.destination;

        // load the local state (or TODO: refill from current state)
        let local_state: SnapshotState =
            bincode::deserialize(&snapshot_data_source).map_err(|error| ReadError::InvalidFile(error.to_string()))?;

        // load comparison snapshot and handle partial synchronization
        match bincode::deserialize::<SnapshotState>(&snapshot_data_compare) {
            Ok(compare_state) => {
                // this is the handlers output
                let mut output_map: HashMap<VaultId, PKey<Provider>> = HashMap::new();
                let mut output_view: DbView<Provider> = DbView::new();
                let mut output_store: Store = Store::new();

                // create new snapshot to write
                let mut output_state = SnapshotState::default();

                // collect all allowed entries as passed by message
                let mut output_data = local_state.0;

                let compare = compare_state.0;

                // add all allowed entries to the output
                for id in msg.allowed {
                    if let Some(data) = compare.get(&id) {
                        output_data.insert(id, data.clone());

                        let (map, view, store) = data;
                        output_map.extend((map.clone()).into_iter());
                        output_view.vaults.extend(view.vaults.clone().into_iter());

                        // changed api
                        output_store.merge(store.clone());
                    }
                }

                // add all local state to the output
                for id in output_data.keys() {
                    if let Some(data) = compare.get(id) {
                        output_state.add_data(*id, data.clone());

                        let (map, view, store) = data;
                        output_map.extend((map.clone()).into_iter());
                        output_view.vaults.extend(view.vaults.clone().into_iter());

                        // changed api
                        output_store.merge(store.clone());
                    }
                }

                // set current state
                self.state = output_state;

                let write_msg = WriteSnapshot {
                    key: dst_config.key,
                    filename: dst_config.filename,
                    path: dst_config.path,
                };

                // write the new state to disk
                <Self as Handler<WriteSnapshot>>::handle(self, write_msg, ctx)
                    .map_err(|error| ReadError::InvalidFile(error.to_string()))?;

                // return Ok(self.state.serialize());
                Ok(ReturnReadSnapshot {
                    data: Box::new((output_map, output_view, output_store)),
                    id: msg.id,
                })
            }
            Err(error) => Err(ReadError::InvalidFile(error.to_string())),
        }
    }
}

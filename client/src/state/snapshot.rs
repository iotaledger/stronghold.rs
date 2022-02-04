// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{
    state::secure::Store,
    sync::{self, BidiMapping, Di, Mapper, MergeLayer, SelectOne, SelectOrMerge},
    Provider,
};

use engine::{
    snapshot::{self, read_from, write_to, Key, ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{ClientId, DbView, Key as PKey, RecordId, VaultId},
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, path::Path};
use thiserror::Error as DeriveError;

/// Wrapper for the [`SnapshotState`] data structure.
#[derive(Default)]
pub struct Snapshot {
    pub state: SnapshotState,
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(pub(crate) HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

impl Snapshot {
    /// Creates a new [`Snapshot`] from a buffer of [`SnapshotState`] state.
    pub fn new(state: SnapshotState) -> Self {
        Self { state }
    }

    /// Gets the state component parts as a tuple.
    pub fn get_state(&mut self, id: ClientId) -> (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (HashMap::default(), DbView::default(), Store::default()),
        }
    }

    /// Checks to see if the [`ClientId`] exists in the snapshot hashmap.
    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> Result<Self, ReadError> {
        let state = match path {
            Some(p) => read_from(p, &key, &[])?,
            None => read_from(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let data =
            SnapshotState::deserialize(state).map_err(|_| ReadError::CorruptedContent("Decryption failed.".into()))?;

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(&self, name: Option<&str>, path: Option<&Path>, key: Key) -> Result<(), WriteError> {
        let data = self
            .state
            .serialize()
            .map_err(|_| WriteError::CorruptedData("Serialization failed.".into()))?;

        // TODO: This is a hack and probably should be removed when we add proper error handling.
        let f = move || match path {
            Some(p) => write_to(&data, p, &key, &[]),
            None => write_to(&data, &snapshot::files::get_path(name)?, &key, &[]),
        };

        match f() {
            Ok(()) => Ok(()),
            Err(_) => f().map_err(|e| e.into()),
        }
    }

    // Sync two client states
    pub fn sync_clients(
        &mut self,
        cid0: ClientId,
        cid1: ClientId,
        mapper: BidiMapping<(VaultId, RecordId)>,
        merge_policy: SelectOrMerge<SelectOne>,
    ) {
        let mut source = self.get_client_state(cid0).unwrap();
        let hierarchy = source.get_hierarchy();
        let mapped_hierarchy = mapper.map_hierarchy(hierarchy, Di::R2L);

        let mut target = self.get_client_state(cid1).unwrap();
        let diff = target.get_diff(mapped_hierarchy, &merge_policy);
        let mapped_diff = mapper.map_hierarchy(diff, Di::L2R);

        let mut source = self.get_client_state(cid0).unwrap();
        let exported = source.export_entries(mapped_diff);

        let source_keystore = &self.state.0.get(&cid0).unwrap().0;
        let target_keystore = &self.state.0.get(&cid1).unwrap().0;
        let mapped_exported = mapper.map_exported(source_keystore, target_keystore, exported);

        let mut target = self.get_client_state(cid1).unwrap();
        target.import_entries(mapped_exported);
    }

    pub fn import_snapshot(
        &mut self,
        other: &mut Self,
        mapper: BidiMapping<(ClientId, VaultId, RecordId)>,
        merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    ) {
        let mut source = other.as_snapshot_state();
        let hierarchy = source.get_hierarchy();
        let mapped_hierarchy = mapper.map_hierarchy(hierarchy, Di::R2L);

        let mut target = self.as_snapshot_state();
        let diff = target.get_diff(mapped_hierarchy, &merge_policy);
        let mapped_diff = mapper.map_hierarchy(diff, Di::L2R);

        let mut source = other.as_snapshot_state();
        let exported = source.export_entries(mapped_diff);

        let source_keystore = other.get_key_provider();
        let target_keystore = self.get_key_provider();
        let mapped_exported = mapper.map_exported(source_keystore, target_keystore, exported);

        let mut target = self.as_snapshot_state();
        target.import_entries(mapped_exported);
    }

    fn as_snapshot_state(&mut self) -> sync::SnapshotState {
        let client_states = self
            .state
            .0
            .iter_mut()
            .map(|(&cid, (keystore, db, _))| {
                let state = sync::ClientState { keystore, db };
                (cid, state)
            })
            .collect();
        sync::SnapshotState { client_states }
    }

    fn get_key_provider(&self) -> HashMap<ClientId, &HashMap<VaultId, PKey<Provider>>> {
        self.state
            .0
            .iter()
            .map(|(&cid, (keystore, _, _))| (cid, keystore))
            .collect()
    }

    fn get_client_state(&mut self, id: ClientId) -> Option<sync::ClientState> {
        let state = self.state.0.get_mut(&id)?;
        Some(sync::ClientState {
            keystore: &state.0,
            db: &mut state.1,
        })
    }
}

impl SnapshotState {
    /// Creates a new snapshot state.
    pub fn new(id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    /// Adds data to the snapshot state hashmap.
    pub fn add_data(&mut self, id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) {
        self.0.insert(id, data);
    }

    /// Serializes the snapshot state into bytes.
    pub fn serialize(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Deserializes the snapshot state from bytes.
    pub fn deserialize(data: Vec<u8>) -> bincode::Result<Self> {
        bincode::deserialize(&data)
    }
}

#[derive(Debug, DeriveError)]
pub enum ReadError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("corrupted file: {0}")]
    CorruptedContent(String),

    #[error("invalid file {0}")]
    InvalidFile(String),
}

impl From<EngineReadError> for ReadError {
    fn from(e: EngineReadError) -> Self {
        match e {
            EngineReadError::CorruptedContent(reason) => ReadError::CorruptedContent(reason),
            EngineReadError::InvalidFile => ReadError::InvalidFile("Not a Snapshot.".into()),
            EngineReadError::Io(io) => ReadError::Io(io),
            EngineReadError::UnsupportedVersion { expected, found } => ReadError::InvalidFile(format!(
                "Unsupported version: expected {:?}, found {:?}.",
                expected, found
            )),
        }
    }
}

#[derive(Debug, DeriveError)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("corrupted data: {0}")]
    CorruptedData(String),
}

impl From<EngineWriteError> for WriteError {
    fn from(e: EngineWriteError) -> Self {
        match e {
            EngineWriteError::Io(io) => WriteError::Io(io),
            EngineWriteError::CorruptedData(e) => WriteError::CorruptedData(e),
            EngineWriteError::GenerateRandom(_) => WriteError::Io(io::ErrorKind::Other.into()),
        }
    }
}

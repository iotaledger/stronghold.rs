// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{
    state::secure::Store,
    sync::{self, MergeClientsMapper, MergeLayer, MergeSnapshotsMapper, SelectOne, SelectOrMerge},
    Provider,
};

use engine::{
    snapshot::{self, read_from, write_to, Key, ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{ClientId, DbView, Key as PKey, VaultId},
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

    /// Sync two client states.
    pub fn sync_clients(
        &mut self,
        cid0: ClientId,
        cid1: ClientId,
        mapper: Option<MergeClientsMapper>,
        merge_policy: SelectOrMerge<SelectOne>,
    ) {
        let mut state0 = self.state.0.remove(&cid0).unwrap();
        // Init target client if it does not exists yet.
        self.state.0.entry(cid1).or_default();
        let mut state1 = self.state.0.remove(&cid1).unwrap();

        let source: sync::ClientState = (&mut state0).into();
        let mut target: sync::ClientState = (&mut state1).into();

        let hierarchy = source.get_hierarchy();
        let diff = target.get_diff(hierarchy, mapper.as_ref(), &merge_policy);
        let exported = source.export_entries(Some(diff));
        target.import_entries(exported, &merge_policy, mapper.as_ref(), Some(source.keystore));

        self.state.0.insert(cid0, state0);
        self.state.0.insert(cid1, state1);
    }

    /// Sync the local state with another snapshot, which imports the entries from `other` to `local`.
    pub fn sync_with_snapshot(
        &mut self,
        other: &mut SnapshotState,
        mapper: Option<MergeSnapshotsMapper>,
        merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    ) {
        let source: sync::SnapshotState = other.into();
        let mut target: sync::SnapshotState = (&mut self.state).into();

        let hierarchy = source.get_hierarchy();
        let diff = target.get_diff(hierarchy, mapper.as_ref(), &merge_policy);
        let exported = source.export_entries(Some(diff));

        target.import_entries(
            exported,
            &merge_policy,
            mapper.as_ref(),
            Some(&source.into_key_provider()),
        );
    }

    /// Export the entries specified in the diff to a blank snapshot state.
    /// This re-encrypts the entries with new vault-keys that are inserted in the new
    /// snapshot state alongside with the exported records.
    ///
    /// Deserialize, encrypt and compress the new state to a bytestring.
    pub fn export_to_serialized_state(
        &mut self,
        diff: <sync::SnapshotState as MergeLayer>::Hierarchy,
        key: Key,
    ) -> Vec<u8> {
        let exported = sync::SnapshotState::from(&mut self.state).export_entries(Some(diff));
        let mut blank_state = SnapshotState(HashMap::default());
        let old_key_store = self.state.0.iter().map(|(cid, state)| (*cid, &state.0)).collect();
        sync::SnapshotState::from(&mut blank_state).import_entries(
            exported,
            &SelectOrMerge::Replace,
            None,
            Some(&old_key_store),
        );
        let data = self.state.serialize().unwrap();
        let compressed_plain = engine::snapshot::compress(data.as_slice());
        let mut buffer = Vec::new();
        engine::snapshot::write(&compressed_plain, &mut buffer, &key, &[]).unwrap();
        buffer
    }

    /// Import from serialized snapshot state.
    pub fn import_from_serialized_state(
        &mut self,
        bytes: Vec<u8>,
        key: Key,
        mapper: Option<MergeSnapshotsMapper>,
        merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    ) {
        let pt = engine::snapshot::read(&mut bytes.as_slice(), &key, &[]).unwrap();
        let data = engine::snapshot::decompress(&pt).unwrap();
        let other_snapshot = &mut SnapshotState::deserialize(data).unwrap();
        let other_state: sync::SnapshotState = other_snapshot.into();
        let exported = other_state.export_entries(None);

        let mut self_state: sync::SnapshotState = (&mut self.state).into();

        self_state.import_entries(
            exported,
            &merge_policy,
            mapper.as_ref(),
            Some(&other_state.into_key_provider()),
        );
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use crate::{state::secure::Store, Provider};
use engine::{
    snapshot::{self, read, read_from, write_to, Key},
    vault::{ClientId, DbView, Key as PKey, VaultId},
};
use std::{collections::HashMap, path::Path};
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("Could Not Load Snapshot. Try another password")]
    LoadFailure,

    #[error("Could Not Synchronize Snapshot: ({0})")]
    SynchronizationFailure(String),

    #[error("Could Not Deserialize Snapshot: ({0})")]
    DeserializationFailure(String),

    #[error("Could Not Serialize Snapshot: ({0})")]
    SerializationFailure(String),

    #[error("Could Not Write Snapshot to File: ({0})")]
    WriteSnapshotFailure(String),

    #[error("Could Not Export Entries ({0})")]
    ExportError(String),

    #[error("could not import snapshot ({0})")]
    ImportFailure(String),

    #[error("Other Failure ({0})")]
    OtherFailure(String),
}

impl From<engine::Error> for SnapshotError {
    fn from(error: engine::Error) -> Self {
        SnapshotError::OtherFailure(error.to_string())
    }
}

/// Wrapper for the [`SnapshotState`] data structure.
#[derive(Default)]
pub struct Snapshot {
    pub state: SnapshotState,
}

/// Data structure that is written to the snapshot.
/// CHANGED: accessing state fields is now allowed inside the crate
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

    /// Reads state from provided data
    pub fn read_from_data(data: Vec<u8>, key: Key, ad: Option<Vec<u8>>) -> Result<Self, SnapshotError> {
        let state = read(&mut std::io::Cursor::new(data), &key, &ad.unwrap_or_default())?;

        Ok(Self::new(SnapshotState::deserialize(state)?))
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> Result<Self, SnapshotError> {
        let state = Self::read_from_name_or_path(name, path, key)?;

        let data = SnapshotState::deserialize(state)?;

        Ok(Self::new(data))
    }

    /// Reads bytes from the specified name snapshot or the specified path
    /// TODO: Add associated data
    pub fn read_from_name_or_path(name: Option<&str>, path: Option<&Path>, key: Key) -> engine::Result<Vec<u8>> {
        match path {
            Some(p) => read_from(p, &key, &[]),
            None => read_from(&snapshot::files::get_path(name)?, &key, &[]),
        }
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(&self, name: Option<&str>, path: Option<&Path>, key: Key) -> Result<(), SnapshotError> {
        let data = self.state.serialize()?;

        // TODO: This is a hack and probably should be removed when we add proper error handling.
        let f = move || {
            match path {
                Some(p) => write_to(&data, p, &key, &[])?,
                None => write_to(&data, &snapshot::files::get_path(name)?, &key, &[])?,
            }
            Ok(())
        };
        match f() {
            Ok(()) => Ok(()),
            Err(_) => f(),
        }
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
    pub fn serialize(&self) -> Result<Vec<u8>, SnapshotError> {
        bincode::serialize(&self).map_err(|error| SnapshotError::DeserializationFailure(error.to_string()))
    }

    /// Deserializes the snapshot state from bytes.
    pub fn deserialize(data: Vec<u8>) -> Result<Self, SnapshotError> {
        bincode::deserialize(&data).map_err(|error| SnapshotError::SerializationFailure(error.to_string()))
    }
}

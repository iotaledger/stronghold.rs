// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{state::secure::Store, Provider};

use engine::{
    snapshot::{self, read_from, write_to, Key, ReadError, WriteError},
    vault::{ClientId, DbView, Key as PKey, VaultId},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, path::Path};
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum ReadSnapshotError {
    #[error("Read Snapshot Error: `{0}`")]
    Read(#[from] ReadError),

    #[error("Deserialize Snapshot Error: `{0}`")]
    Deserialize(#[from] bincode::Error),

    #[error("I/O Error: `{0}`")]
    Io(#[from] io::Error),
}

#[derive(Debug, DeriveError)]
pub enum WriteSnapshotError {
    #[error("Write Snapshot Error: `{0}`")]
    Write(#[from] WriteError),

    #[error("Serialize Snapshot Error: `{0}`")]
    Serialize(#[from] bincode::Error),

    #[error("I/O Error: `{0}`")]
    Io(#[from] io::Error),
}

/// Wrapper for the [`SnapshotState`] data structure.
#[derive(Default)]
pub struct Snapshot {
    pub state: SnapshotState,
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

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
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> Result<Self, ReadSnapshotError> {
        let state = match path {
            Some(p) => read_from(p, &key, &[])?,
            None => read_from(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let data = SnapshotState::deserialize(state)?;

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(
        &self,
        name: Option<&str>,
        path: Option<&Path>,
        key: Key,
    ) -> Result<(), WriteSnapshotError> {
        let data = self.state.serialize()?;

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

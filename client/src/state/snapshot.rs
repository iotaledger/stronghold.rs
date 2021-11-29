// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{state::secure::Store, FatalEngineError, Location, Provider};

use engine::{
    snapshot::{self, read_from, write_to, Key, ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{ClientId, DbView, Key as PKey, RecordId, VaultId},
};

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::{Infallible, TryInto},
    io,
    path::Path,
};
use thiserror::Error as DeriveError;

use super::secure::SecureClient;

#[derive(DeriveError, Debug)]
pub enum WriteWithKeyError {
    #[error("write snapshot failed: {0}")]
    WriteSnapshot(#[from] WriteError),
    #[error("fatal engine error: {0}")]
    Engine(#[from] FatalEngineError),
    #[error("client not found: {0:?}")]
    ClientNotFound(ClientId),
    #[error("vault not found: {0}")]
    VaultNotFound(VaultId),
    #[error("record not found: {0:?}")]
    RecordNotFound(RecordId),
    #[error("invalid key: {0}")]
    InvalidKey(String),
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

    pub fn write_snapshot_with_stored_key(
        &mut self,
        name: Option<&str>,
        path: Option<&Path>,
        key_location: Location,
        key_client: ClientId,
    ) -> Result<(), WriteWithKeyError> {
        let (vid, rid) = SecureClient::resolve_location(key_location);
        let client_data = self
            .state
            .0
            .get_mut(&key_client)
            .ok_or(WriteWithKeyError::ClientNotFound(key_client))?;
        let k = client_data.0.get(&vid).ok_or(WriteWithKeyError::VaultNotFound(vid))?;
        // Get snapshot key from vault.
        let mut key = Vec::new();
        client_data
            .1
            .get_guard::<Infallible, _>(k, vid, rid, |guard| {
                let key_bytes = guard.borrow();
                key.extend_from_slice(&*key_bytes);
                Ok(())
            })
            .map_err(|e| FatalEngineError::from(e.to_string()))?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| WriteWithKeyError::InvalidKey("invalid length".into()))?;

        self.write_to_snapshot(name, path, key)?;
        Ok(())
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{state::secure::Store, utils::EntryShape, Location, Provider};

use engine::{
    snapshot::{self, read, read_from, write_to, Key, ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{ClientId, DbView, Key as PKey, RecordId, VaultId},
};
use std::{
    collections::HashMap,
    convert::TryInto,
    hash::{Hash, Hasher},
    io,
    path::Path,
};
use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("Could Not Load Snapshot. Try another password")]
    FailedToLoad,

    #[error("Could Not Synchronize Snapshot: ({0})")]
    SynchronizationError(String),

    #[error("Could Not Deserialize Snapshot: ({0})")]
    DeserializationFailure(String),

    #[error("Could Not Serialize Snapshot: ({0})")]
    SerializationFailure(String),
}

use serde::{Deserialize, Serialize};

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
    /// Returns the entries for a ['ClientId`] as mapping between [`Location`] and [`EntryShape`]
    pub fn as_entry_shapes<L, H>(&mut self, id: ClientId, locations: L, mut hasher: H) -> HashMap<Location, EntryShape>
    where
        L: AsRef<Vec<Location>>,
        H: Hasher,
    {
        let (keys, mut view, _) = self.get_state(id);
        let mut output = HashMap::new();
        locations
            .as_ref()
            .iter()
            .map(
                |loc| -> Result<(PKey<Provider>, VaultId, RecordId, Location), Box<dyn std::error::Error>> {
                    let vid: VaultId = loc.try_into()?;
                    let rid: RecordId = loc.try_into()?;

                    Ok((keys.get(&vid).unwrap().clone(), vid, rid, loc.clone()))
                },
            )
            .filter(|result| result.is_ok())
            .for_each(|result| {
                let (key, vid, rid, location) = result.unwrap();

                view.get_guard::<String, _>(&key, vid, rid, |data| {
                    let data = data.borrow();

                    data.hash(&mut hasher);

                    output.insert(
                        location.clone(),
                        EntryShape {
                            vid,
                            rid,
                            record_hash: hasher.finish(),
                            record_size: data.len(),
                        },
                    );

                    Ok(())
                })
                .unwrap();
            });

        output
    }

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
    pub fn read_from_data(data: Vec<u8>, key: Key, ad: Option<Vec<u8>>) -> Result<Self, ReadError> {
        let state = read(&mut std::io::Cursor::new(data), &key, &ad.unwrap_or_default())?;

        Ok(Self::new(SnapshotState::deserialize(state).map_err(|_| {
            ReadError::CorruptedContent("Decryption failed.".into())
        })?))
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

    /// Reads bytes from the specified name snapshot or the specified path
    /// TODO: Add associated data
    pub fn read_from_name_or_path(
        name: Option<&str>,
        path: Option<&Path>,
        key: Key,
    ) -> Result<Vec<u8>, engine::snapshot::ReadError> {
        match path {
            Some(p) => read_from(p, &key, &[]),
            None => read_from(&snapshot::files::get_path(name)?, &key, &[]),
        }
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

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{
    actors::VaultError,
    state::secure::Store,
    sync::{
        self, MergeClientsMapper, MergeLayer, MergeSnapshotsMapper, SelectOne, SelectOrMerge, SnapshotStateHierarchy,
    },
    Provider,
};

use crypto::keys::x25519;
use engine::{
    snapshot::{self, read_from, write_to, Key, ReadError as EngineReadError, WriteError as EngineWriteError},
    vault::{ClientId, DbView, Key as PKey, VaultId},
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, path::Path};
use thiserror::Error as DeriveError;

/// Wrapper for the [`SnapshotState`] data structure.
pub struct Snapshot {
    pub state: SnapshotState,
    // Local secret key used to perform Diffie-Hellman key exchanges with remote
    // peers to derive the encryption key for the snapshot sync.
    // **TODO: this is only a mock key and will be stored securely after the upcoming
    // refactoring.**
    pub dh_sk: x25519::SecretKey,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new(SnapshotState::default())
    }
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(pub(crate) HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

impl Snapshot {
    /// Creates a new [`Snapshot`] from a buffer of [`SnapshotState`] state.
    pub fn new(state: SnapshotState) -> Self {
        Self {
            state,
            // TODO: this is only a mock key
            dh_sk: x25519::SecretKey::generate().unwrap(),
        }
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
    /// Return `Ok(`None`)` if the source client does not exist.
    pub fn sync_clients(
        &mut self,
        cid0: ClientId,
        cid1: ClientId,
        mapper: Option<MergeClientsMapper>,
        merge_policy: SelectOrMerge<SelectOne>,
    ) -> Result<Option<()>, VaultError> {
        let mut state0 = match self.state.0.remove(&cid0) {
            Some(state) => state,
            None => return Ok(None),
        };
        // Init target client if it does not exists yet.
        self.state.0.entry(cid1).or_default();
        let mut state1 = self.state.0.remove(&cid1).unwrap();

        let mut source: sync::SyncClientState = (&mut state0).into();
        let mut target: sync::SyncClientState = (&mut state1).into();

        let hierarchy = source.get_hierarchy()?;
        let diff = target.get_diff(hierarchy, mapper.as_ref(), &merge_policy)?;
        let exported = source.export_entries(Some(diff))?;
        target.import_entries(exported, &merge_policy, mapper.as_ref(), Some(source.keystore))?;

        self.state.0.insert(cid0, state0);
        self.state.0.insert(cid1, state1);
        Ok(Some(()))
    }

    /// Sync the local state with another snapshot, which imports the entries from `other` to `local`.
    pub fn sync_with_snapshot(
        &mut self,
        other: &mut SnapshotState,
        mapper: Option<&MergeSnapshotsMapper>,
        merge_policy: &SelectOrMerge<SelectOrMerge<SelectOne>>,
    ) -> Result<(), VaultError> {
        let hierarchy = other.get_hierarchy()?;
        let diff = self.state.get_diff(hierarchy, mapper, merge_policy)?;
        let exported = other.export_entries(Some(diff))?;

        self.state
            .import_entries(exported, merge_policy, mapper, Some(&other.as_key_provider()))?;
        Ok(())
    }

    /// Export the entries specified in the diff to a blank snapshot state.
    /// This re-encrypts the entries with new vault-keys that are inserted in the new
    /// snapshot state alongside with the exported records.
    ///
    /// Deserialize, encrypt and compress the new state to a bytestring.
    pub fn export_to_serialized_state(
        &mut self,
        diff: SnapshotStateHierarchy,
        dh_key: [u8; x25519::PUBLIC_KEY_LENGTH],
    ) -> Result<(Vec<u8>, [u8; x25519::PUBLIC_KEY_LENGTH]), MergeError> {
        let exported = self.state.export_entries(Some(diff))?;
        let old_key_store = self.state.0.iter().map(|(cid, state)| (*cid, &state.0)).collect();
        let mut blank_state = SnapshotState(HashMap::default());
        blank_state.import_entries(exported, &SelectOrMerge::Replace, None, Some(&old_key_store))?;
        let data = self
            .state
            .serialize()
            .map_err(|e| WriteError::CorruptedData(e.to_string()))?;
        let compressed_plain = engine::snapshot::compress(data.as_slice());
        let mut buffer = Vec::new();
        // Create encryption key from Diffie-Hellman handshake with the remote.
        let key = self.diffie_hellman(x25519::PublicKey::from_bytes(dh_key));
        engine::snapshot::write(&compressed_plain, &mut buffer, key.as_bytes(), &[]).map_err(WriteError::from)?;
        Ok((buffer, self.get_dh_pub_key().to_bytes()))
    }

    /// Import from serialized snapshot state.
    pub fn import_from_serialized_state(
        &mut self,
        bytes: Vec<u8>,
        dh_key: [u8; x25519::PUBLIC_KEY_LENGTH],
        mapper: Option<&MergeSnapshotsMapper>,
        merge_policy: &SelectOrMerge<SelectOrMerge<SelectOne>>,
    ) -> Result<(), MergeError> {
        // Derive encryption key from Diffie-Hellman handshake with the remote.
        let key = self.diffie_hellman(x25519::PublicKey::from_bytes(dh_key));
        let pt = engine::snapshot::read(&mut bytes.as_slice(), key.as_bytes(), &[]).map_err(ReadError::from)?;
        let data = engine::snapshot::decompress(&pt).map_err(|e| ReadError::CorruptedContent(e.to_string()))?;
        let mut other_state =
            SnapshotState::deserialize(data).map_err(|e| ReadError::CorruptedContent(e.to_string()))?;
        let exported = other_state.export_entries(None)?;

        self.state
            .import_entries(exported, merge_policy, mapper, Some(&other_state.as_key_provider()))?;
        Ok(())
    }

    pub fn get_dh_pub_key(&self) -> x25519::PublicKey {
        self.dh_sk.public_key()
    }

    fn diffie_hellman(&self, other: x25519::PublicKey) -> x25519::SharedSecret {
        self.dh_sk.diffie_hellman(&other)
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

#[derive(Debug, DeriveError)]
pub enum MergeError {
    #[error("parsing snapshot state from bytestring failed: {0}")]
    ReadExported(#[from] ReadError),

    #[error("converting snapshot state into bytestring failed: {0}")]
    WriteExported(#[from] WriteError),

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
}

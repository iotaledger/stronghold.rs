// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{
    state::{key_store::KeyStore, secure::Store},
    Location, Provider,
};

use engine::{
    snapshot::{
        self, read, read_from as read_from_file, write, write_to as write_to_file, Key, ReadError as EngineReadError,
        WriteError as EngineWriteError,
    },
    vault::{ClientId, DbView, Key as PKey, RecordHint, RecordId, VaultId},
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, io, ops::Deref, path::Path};
use stronghold_utils::random;
use thiserror::Error as DeriveError;

type EncryptedClientState = (Vec<u8>, Store);
pub type ClientState = (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store);

/// Wrapper for the [`SnapshotState`] data structure.
pub struct Snapshot {
    // Keys for vaults in db and for the encrypted client states.
    keystore: KeyStore,
    // Db with snapshot keys.
    db: DbView<Provider>,
    // Loaded snapshot states with each client state separately encrypted.
    states: HashMap<ClientId, EncryptedClientState>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            keystore: KeyStore::new(),
            db: DbView::new(),
            states: HashMap::new(),
        }
    }
}

pub enum UseKey {
    Key(snapshot::Key),
    Stored(Location),
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(HashMap<ClientId, ClientState>);

impl Snapshot {
    /// Creates a new [`Snapshot`] from a buffer of [`SnapshotState`] state.
    pub fn from_state(
        state: SnapshotState,
        snapshot_key: Key,
        write_key: Option<(VaultId, RecordId)>,
    ) -> Result<Self, SnapshotError> {
        let mut snapshot = Snapshot::default();
        if let Some((vid, rid)) = write_key {
            let key = snapshot.keystore.create_key(vid);
            snapshot
                .db
                .write(key, vid, rid, &snapshot_key, RecordHint::new("").unwrap())
                .unwrap();
        }
        for (client_id, state) in state.0 {
            snapshot.add_data(client_id, state)?;
        }
        Ok(snapshot)
    }

    /// Gets the state component parts as a tuple.
    pub fn get_snapshot_state(&self) -> Result<SnapshotState, SnapshotError> {
        let mut state = SnapshotState::default();
        for client_id in self.states.keys() {
            let id = *client_id;
            let client_state = self.get_state(id)?;
            state.0.insert(id, client_state);
        }
        Ok(state)
    }

    /// Gets the state component parts as a tuple.
    pub fn get_state(&self, id: ClientId) -> Result<ClientState, SnapshotError> {
        let vid = VaultId(id.0);
        let ((encrypted, store), key) = match self
            .states
            .get(&id)
            .and_then(|state| self.keystore.get_key(vid).map(|pkey| (state, pkey)))
            .and_then(|(state, pkey)| {
                let pkey = &pkey.key;
                pkey.borrow().deref().try_into().ok().map(|k| (state, k))
            }) {
            Some(t) => t,
            None => return Ok((HashMap::default(), DbView::default(), Store::default())),
        };
        let decrypted = read(&mut encrypted.as_slice(), &key, &[])?;
        let (keys, db) = bincode::deserialize(&decrypted)?;
        Ok((keys, db, store.clone()))
    }

    /// Checks to see if the [`ClientId`] exists in the snapshot hashmap.
    pub fn has_data(&self, cid: ClientId) -> bool {
        self.states.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(
        name: Option<&str>,
        path: Option<&Path>,
        key: Key,
        write_key: Option<(VaultId, RecordId)>,
    ) -> Result<Self, SnapshotError> {
        let data = match path {
            Some(p) => read_from_file(p, &key, &[])?,
            None => read_from_file(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let state = bincode::deserialize(&data)?;
        Snapshot::from_state(state, key, write_key)
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(
        &mut self,
        name: Option<&str>,
        path: Option<&Path>,
        use_key: UseKey,
    ) -> Result<(), SnapshotError> {
        let state = self.get_snapshot_state()?;
        let data = bincode::serialize(&state)?;

        let key = match use_key {
            UseKey::Key(k) => k,
            UseKey::Stored(loc) => {
                let (vid, rid) = loc.resolve();
                let pkey = self.keystore.get_key(vid).ok_or(SnapshotError::SnapshotKey(vid, rid))?;
                let mut data = Vec::new();
                self.db
                    .get_guard::<Infallible, _>(pkey, vid, rid, |guarded_data| {
                        let guarded_data = guarded_data.borrow();
                        data.extend_from_slice(&*guarded_data);
                        Ok(())
                    })
                    .map_err(|e| SnapshotError::Vault(format!("{}", e)))?;
                data.try_into().map_err(|_| SnapshotError::SnapshotKey(vid, rid))?
            }
        };

        // TODO: This is a hack and probably should be removed when we add proper error handling.
        let f = move || match path {
            Some(p) => write_to_file(&data, p, &key, &[]),
            None => write_to_file(&data, &snapshot::files::get_path(name)?, &key, &[]),
        };

        match f() {
            Ok(()) => Ok(()),
            Err(_) => f().map_err(|e| e.into()),
        }
    }

    /// Adds data to the snapshot state hashmap.
    pub fn add_data(
        &mut self,
        id: ClientId,
        (keys, db, store): (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store),
    ) -> Result<(), SnapshotError> {
        let bytes = bincode::serialize(&(keys, db))?;
        let vault_id = VaultId(id.0);
        let key: snapshot::Key = random::random();
        let mut buffer = Vec::new();
        write(&bytes, &mut buffer, &key, &[])?;
        let pkey = PKey::load(key.into()).expect("Provider::box_key_len == KEY_SIZE == 32");
        self.keystore.entry_or_insert_key(vault_id, pkey);
        self.states.insert(id, (buffer, store));
        Ok(())
    }

    /// Adds data to the snapshot state hashmap.
    pub fn store_snapshot_key(
        &mut self,
        snapshot_key: snapshot::Key,
        vault_id: VaultId,
        record_id: RecordId,
    ) -> Result<(), SnapshotError> {
        let key = self.keystore.create_key(vault_id);
        self.db
            .write(
                key,
                vault_id,
                record_id,
                &snapshot_key,
                RecordHint::new("").expect("0 <= 24"),
            )
            .map_err(|e| SnapshotError::Vault(format!("{}", e)))?;
        Ok(())
    }
}

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("corrupted file: {0}")]
    CorruptedContent(String),

    #[error("invalid file {0}")]
    InvalidFile(String),

    #[error("missing or invalid snapshot key in {0:?} {1:?}")]
    SnapshotKey(VaultId, RecordId),

    #[error("vault error: {0}")]
    Vault(String),
}

impl From<bincode::Error> for SnapshotError {
    fn from(e: bincode::Error) -> Self {
        SnapshotError::CorruptedContent(format!("bincode error: {}", e))
    }
}

impl From<EngineReadError> for SnapshotError {
    fn from(e: EngineReadError) -> Self {
        match e {
            EngineReadError::CorruptedContent(reason) => SnapshotError::CorruptedContent(reason),
            EngineReadError::InvalidFile => SnapshotError::InvalidFile("Not a Snapshot.".into()),
            EngineReadError::Io(io) => SnapshotError::Io(io),
            EngineReadError::UnsupportedVersion { expected, found } => SnapshotError::InvalidFile(format!(
                "Unsupported version: expected {:?}, found {:?}.",
                expected, found
            )),
        }
    }
}

impl From<EngineWriteError> for SnapshotError {
    fn from(e: EngineWriteError) -> Self {
        match e {
            EngineWriteError::Io(io) => SnapshotError::Io(io),
            EngineWriteError::CorruptedData(e) => SnapshotError::CorruptedContent(e),
            EngineWriteError::GenerateRandom(_) => SnapshotError::Io(io::ErrorKind::Other.into()),
        }
    }
}

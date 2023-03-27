// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot,
    vault::{ClientId, DbView, Key as PKey, VaultId},
};

use crate::{line_error, state::client::Store, Provider};

use std::path::Path;

use std::collections::HashMap;

pub struct Snapshot {
    pub state: SnapshotState,
}

#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

impl Snapshot {
    /// Creates a new `Snapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: SnapshotState) -> Self {
        Self { state }
    }

    pub fn get_state(&mut self, id: ClientId) -> (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (HashMap::default(), DbView::default(), Store::default()),
        }
    }

    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: &snapshot::Key) -> crate::Result<Self> {
        let state = match path {
            Some(p) => snapshot::decrypt_file(p, key, &[]).map_err(|e| engine::Error::from(e))?,
            None => snapshot::decrypt_file(&snapshot::files::get_path(name)?, key, &[])
                .map_err(|e| engine::Error::from(e))?,
        };

        let data = SnapshotState::deserialize(state.as_ref());

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(&self, name: Option<&str>, path: Option<&Path>, key: &snapshot::Key) -> crate::Result<()> {
        let data = self.state.serialize();

        // TODO: This is a hack and probably should be removed when we add proper error handling.
        let f = move || {
            match path {
                Some(p) => snapshot::encrypt_file(&data, p, key, &[]).map_err(|e| engine::Error::from(e))?,
                None => snapshot::encrypt_file(&data, &snapshot::files::get_path(name)?, key, &[])
                    .map_err(|e| engine::Error::from(e))?,
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
    pub fn new(id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    pub fn add_data(&mut self, id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) {
        self.0.insert(id, data);
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: &[u8]) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

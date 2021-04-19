// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{self, read_from, write_to, Key},
    vault::{nvault::DbView, ClientId, Key as PKey, VaultId},
};

use crate::{line_error, state::client::Store, state::old_snapshot::OldSnapshotState, Provider};

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
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<Self> {
        let (old, state) = match path {
            Some(p) => (snapshot::is_old_version(p)?, read_from(p, &key, &[])?),
            None => (
                snapshot::is_old_version(&snapshot::files::get_path(name)?)?,
                read_from(&snapshot::files::get_path(name)?, &key, &[])?,
            ),
        };

        let data = if old {
            let old = OldSnapshotState::deserialize(state);
            let state = old.convert();
            SnapshotState::from_old(state)
        } else {
            SnapshotState::deserialize(state)
        };

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(&self, name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<()> {
        let data = self.state.serialize();

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
    pub fn new(id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    pub fn from_old(state: HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>) -> Self {
        Self(state)
    }

    pub fn add_data(&mut self, id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) {
        self.0.insert(id, data);
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

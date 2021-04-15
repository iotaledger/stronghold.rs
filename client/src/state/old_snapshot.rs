// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{self, read_from, write_to, Key},
    vault::{ClientId, Key as PKey, ReadResult, VaultId},
};

use crate::{line_error, state::client::Client, Provider};

use std::path::Path;

use std::collections::HashMap;

#[derive(Clone)]
pub struct Snapshot {
    pub state: SnapshotState,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug)]
pub struct SnapshotState(
    HashMap<
        ClientId,
        (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    >,
);

impl Snapshot {
    /// Creates a new `Snapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: SnapshotState) -> Self {
        Self { state }
    }

    pub fn get_state(
        &mut self,
        id: ClientId,
    ) -> (
        Client,
        HashMap<VaultId, PKey<Provider>>,
        HashMap<VaultId, Vec<ReadResult>>,
    ) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (Client::new(id), HashMap::default(), HashMap::default()),
        }
    }

    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<Self> {
        let state = match path {
            Some(p) => read_from(p, &key, &[])?,
            None => read_from(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let data = SnapshotState::deserialize(state);

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(self, name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<()> {
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
    pub fn new(
        id: ClientId,
        data: (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    ) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    pub fn add_data(
        &mut self,
        id: ClientId,
        data: (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    ) {
        self.0.insert(id, data);
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{read_from, snapshot_dir, write_to, Key},
    vault::{Key as PKey, ReadResult},
};

use crate::{client::Client, line_error, ClientId, Provider, VaultId};

use std::path::{Path, PathBuf};

use std::collections::{BTreeMap, HashMap};

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
            BTreeMap<VaultId, PKey<Provider>>,
            BTreeMap<PKey<Provider>, Vec<ReadResult>>,
        ),
    >,
    /* pub ids: Vec<ClientId>,
     * pub clients: Vec<Client>,
     * pub caches: Vec<BTreeMap<PKey<Provider>, Vec<ReadResult>>>,
     * pub stores: Vec<BTreeMap<VaultId, PKey<Provider>>>, */
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
        BTreeMap<VaultId, PKey<Provider>>,
        BTreeMap<PKey<Provider>, Vec<ReadResult>>,
    ) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (Client::new(id), BTreeMap::default(), BTreeMap::default()),
        }
    }

    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Gets the `Snapshot` path given a `Option<String>` as the snapshot name.  Defaults to
    /// `$HOME/.engine/snapshot/backup.snapshot` and returns a `PathBuf`.
    pub fn get_snapshot_path(name: Option<String>) -> PathBuf {
        let path = snapshot_dir().expect("Unable to get the snapshot directory");
        if let Some(name) = name {
            path.join(format!("{}.stronghold", name))
        } else {
            path.join("snapshot.stronghold")
        }
    }

    /// Reads the data from the specified `&PathBuf` when given a `&str` password.  Returns a new `Snapshot`.
    pub fn read_from_snapshot(path: &Path, key: Key) -> crate::Result<Self> {
        let state = read_from(path, &key, &[])?;

        let data = SnapshotState::deserialize(state);

        Ok(Self::new(data))
    }

    /// Writes the data to the specified `&PathBuf` when given a `&str` password creating a new snapshot file.
    pub fn write_to_snapshot(self, path: &Path, key: Key) {
        let data = self.state.serialize();

        write_to(&data, path, &key, &[])
            .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");
    }
}

impl SnapshotState {
    pub fn new(
        id: ClientId,
        data: (
            Client,
            BTreeMap<VaultId, PKey<Provider>>,
            BTreeMap<PKey<Provider>, Vec<ReadResult>>,
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
            BTreeMap<VaultId, PKey<Provider>>,
            BTreeMap<PKey<Provider>, Vec<ReadResult>>,
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

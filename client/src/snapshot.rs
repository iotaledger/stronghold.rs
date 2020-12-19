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

use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Snapshot {
    pub state: SnapshotState,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct SnapshotState {
    pub ids: Vec<ClientId>,
    pub clients: Vec<Client>,
    pub caches: Vec<BTreeMap<PKey<Provider>, Vec<ReadResult>>>,
    pub stores: Vec<BTreeMap<VaultId, PKey<Provider>>>,
}

impl Snapshot {
    /// Creates a new `Snapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: SnapshotState) -> Self {
        Self { state }
    }

    pub fn get_state(
        self,
        id: ClientId,
    ) -> (
        Client,
        BTreeMap<PKey<Provider>, Vec<ReadResult>>,
        BTreeMap<VaultId, PKey<Provider>>,
    ) {
        let idx = self.state.ids.iter().position(|cid| cid == &id);

        if let Some(idx) = idx {
            (
                self.state.clients[idx].clone(),
                self.state.caches[idx].clone(),
                self.state.stores[idx].clone(),
            )
        } else {
            (Client::new(id), BTreeMap::new(), BTreeMap::new())
        }
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
        ids: Vec<ClientId>,
        clients: Vec<Client>,
        stores: Vec<BTreeMap<VaultId, PKey<Provider>>>,
        caches: Vec<BTreeMap<PKey<Provider>, Vec<ReadResult>>>,
    ) -> Self {
        Self {
            ids,
            clients,
            stores,
            caches,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

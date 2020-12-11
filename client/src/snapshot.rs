// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use engine::snapshot::{read_from, snapshot_dir, write_to, Key};

use crate::line_error;

use std::path::{Path, PathBuf};

pub struct Snapshot {
    pub state: Option<SnapshotData>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotData {
    pub cache: Vec<u8>,
    pub store: Vec<u8>,
}

impl Snapshot {
    /// Creates a new `Snapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: Option<SnapshotData>) -> Self {
        Self { state }
    }

    pub fn get_state(self) -> SnapshotData {
        if let Some(state) = self.state {
            state
        } else {
            SnapshotData::default()
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
    pub fn read_from_snapshot(path: &Path, key: Key) -> Self {
        let state = read_from(path, &key, &[])
            .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");

        let data = SnapshotData::deserialize(state);

        Self::new(Some(data))
    }

    /// Writes the data to the specified `&PathBuf` when given a `&str` password creating a new snapshot file.
    pub fn write_to_snapshot(self, path: &Path, key: Key) {
        let data = self.state.expect(line_error!()).serialize();

        write_to(&data, path, &key, &[])
            .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");
    }
}

impl SnapshotData {
    pub fn new(cache: Vec<u8>, store: Vec<u8>) -> Self {
        SnapshotData { cache, store }
    }

    pub fn get_cache(&self) -> Vec<u8> {
        self.cache.clone()
    }

    pub fn get_store(&self) -> Vec<u8> {
        self.store.clone()
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

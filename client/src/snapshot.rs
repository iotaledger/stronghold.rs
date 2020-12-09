// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{write_to, read_from, snapshot_dir, Key},
    vault::BoxProvider,
};

use std::{fs::OpenOptions, path::{Path, PathBuf}};

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub state: Vec<u8>,
}

impl Snapshot {
    /// Creates a new `Snapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: Vec<u8>) -> Self {
        Self { state }
    }

    /// Gets the state from the `Snapshot`
    pub fn get_state(self) -> Vec<u8> {
        self.state
    }

    /// Gets the `Snapshot` path given a `Option<String>` as the snapshot name.  Defaults to
    /// `$HOME/.engine/snapshot/backup.snapshot` and returns a `PathBuf`.
    pub fn get_snapshot_path(name: Option<String>) -> PathBuf {
        let path = snapshot_dir().expect("Unable to get the snapshot directory");
        if let Some(name) = name {
            path.join(format!("{}.snapshot", name))
        } else {
            path.join("backup.snapshot")
        }
    }

    /// Reads the data from the specified `&PathBuf` when given a `&str` password.  Returns a new `Snapshot`.
    pub fn read_from_snapshot(path: &Path, key: Key) -> Self
    {
        let state = read_from(path, &key, &vec![])
            .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");
        Self::new(state)
    }

    /// Writes the data to the specified `&PathBuf` when given a `&str` password creating a new snapshot file.
    pub fn write_to_snapshot(self, path: &Path, key: Key) {
        write_to(&self.state, path, &key, &vec![])
            .expect("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.");
    }
}

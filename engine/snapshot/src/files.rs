// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Get the preferred Stronghold home directory
///
/// Defaults to a sub-directory named `.stronghold` under the user's home directory (see
/// [`dirs_next::home_dir`](../dirs_next/fn.home_dir.html), but can be overridden by the `STRONGHOLD` environment
/// variable.
pub fn home_dir() -> crate::Result<PathBuf> {
    let home = match std::env::var("STRONGHOLD") {
        Ok(h) => h.into(),
        Err(_) => dirs_next::home_dir().expect("Failed to get home directory"),
    };
    let home_dir = home.join(".stronghold");

    verify_or_create(&home_dir)?;

    Ok(home_dir)
}

/// Get the preferred snapshot directory
///
/// Defaults to the `snapshots` subdirectory under the preferred Stronghold home directory as
/// returned by [`home_dir`](fn.home_dir.html).
pub fn snapshot_dir() -> crate::Result<PathBuf> {
    let home_dir = home_dir()?;
    let snapshot_dir = home_dir.join("snapshots");

    verify_or_create(&snapshot_dir)?;

    Ok(snapshot_dir)
}

fn verify_or_create(dir: &Path) -> crate::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    Ok(fs::create_dir_all(dir)?)
}

/// Construct the path to a snapshot file with the specifed name (defaults to `main`) under
/// the directory specified by the (`snapshot_dir`)[fn.snapshot_dir.html] function.
pub fn get_path(name: Option<&str>) -> crate::Result<PathBuf> {
    snapshot_dir().map(|p| p.join(format!("{}.stronghold", name.unwrap_or("main"))))
}

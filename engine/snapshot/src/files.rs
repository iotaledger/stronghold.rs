// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// get the home directory of the user's device
pub fn home_dir() -> crate::Result<PathBuf> {
    let home = match std::env::var("STRONGHOLD") {
        Ok(h) => h.into(),
        Err(_) => dirs::home_dir().unwrap(),
    };
    let home_dir = home.join(format!(".{}", "engine"));

    verify_or_create(&home_dir)?;

    Ok(home_dir)
}

/// get the snapshot dir of the user's device
pub fn snapshot_dir() -> crate::Result<PathBuf> {
    let home_dir = home_dir()?;
    let snapshot_dir = home_dir.join("snapshots");

    verify_or_create(&snapshot_dir)?;

    Ok(snapshot_dir)
}

/// verify that the folder exists or create it.
fn verify_or_create(dir: &Path) -> crate::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    Ok(fs::create_dir_all(dir)?)
}

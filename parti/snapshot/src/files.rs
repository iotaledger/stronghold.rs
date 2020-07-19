use dirs;

use std::{
    fs,
    path::{Path, PathBuf},
};

/// get the home directory of the user's device
pub fn home_dir() -> crate::Result<PathBuf> {
    let home = dirs::home_dir().unwrap();
    let home_dir = home.join(format!(".{}", "parti"));

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

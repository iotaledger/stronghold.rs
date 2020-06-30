use dirs;

use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn main_dir() -> crate::Result<PathBuf> {
    let home = dirs::home_dir().unwrap();
    let main_dir = home.join(format!(".{}", "parti"));

    verify_or_create(&main_dir);

    Ok(main_dir)
}

pub fn snapshot_dir() -> crate::Result<PathBuf> {
    let main_dir = main_dir()?;
    let snapshot_dir = main_dir.join("snapshots");

    verify_or_create(&snapshot_dir)?;

    Ok(snapshot_dir)
}

pub fn key_dir() -> crate::Result<PathBuf> {
    let main_dir = main_dir()?;
    let key_dir = main_dir.join("keys");

    verify_or_create(&key_dir)?;

    Ok(key_dir)
}

pub fn verify_or_create(dir: &Path) -> crate::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    Ok(fs::create_dir_all(dir)?)
}

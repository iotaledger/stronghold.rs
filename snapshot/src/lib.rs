mod error;
mod files;
mod snapshot;

pub use error::{Error, Result};

pub use {
    files::{home_dir, snapshot_dir},
    snapshot::{decrypt, encrypt},
};

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("Snapshot Error: `{0}`")]
    SnapshotError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(String),
    #[error("Random Error: `{0}`")]
    RNGError(#[from] Box<dyn std::error::Error>),
}

pub type Result<T> = std::result::Result<T, Error>;

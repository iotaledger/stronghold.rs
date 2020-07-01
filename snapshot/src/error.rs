use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("`{0}`")]
    SnapshotError(String),
    #[error("Serde Error: `{0}`")]
    SerdeError(#[from] serde_json::Error),
    #[error("Crypto Error: `{0}`")]
    CryptoError(String),
    #[error("Glob Error: `{0}`")]
    GlobError(#[from] glob::PatternError),
}

pub type Result<T> = std::result::Result<T, Error>;

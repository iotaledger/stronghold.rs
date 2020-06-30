use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum Error {
    #[error("IOError: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("`{0}`")]
    SnapshotError(String),
    #[error("Serde Error: `{0}`")]
    SerdeError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

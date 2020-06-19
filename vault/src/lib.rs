use thiserror::Error as DeriveError;

pub mod base64;
pub mod crypt_box;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Database Error: `{0}`")]
    DatabaseError(String),
    #[error("Version Error: `{0}`")]
    VersionError(String),
    #[error("Base64Error")]
    Base64Error,
    #[error("Interface Error")]
    InterfaceError,
}

pub type Result<T> = std::result::Result<T, Error>;

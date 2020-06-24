use thiserror::Error as DeriveError;

mod base64;
mod crypt_box;
mod types;
mod vault;

pub use crate::{
    base64::{Base64Decodable, Base64Encodable},
    crypt_box::{BoxProvider, Key},
    types::utils::{Id, IndexHint},
    vault::{
        DBReader, DBView, DBWriter, DeleteRequest, ListResult, ReadRequest, ReadResult,
        WriteRequest,
    },
};

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Database Error: `{0}`")]
    DatabaseError(String),
    #[error("Version Error: `{0}`")]
    VersionError(String),
    #[error("Chain error: `{0}`")]
    ChainError(String),
    #[error("Base64Error")]
    Base64Error,
    #[error("Interface Error")]
    InterfaceError,
    #[error("Other Error")]
    OtherError(String),
    #[error("Crypto Error: `{0}`")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

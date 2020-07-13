// Vault is an in-memory database format which is designed to work
// without a central server.

// the format of this databse is based off of ordered data chains.

// A Chain of records starts with an `InitTransaction`.  Changes to the data is represented
// as a descendent of the InitTransaction. The data also features a counter field.
// Any transaction that isn't a descendent of the InitTransaction is ignored and is not considered valid.

use thiserror::Error as DeriveError;

mod base64;
mod crypto_box;
mod types;
mod vault;

pub use crate::{
    base64::{Base64Decodable, Base64Encodable},
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::utils::{Id, RecordHint},
    vault::{
        DBReader, DBView, DBWriter, DeleteRequest, Entry, ListResult, ReadRequest, ReadResult,
        WriteRequest,
    },
};

// Errors for the Vault Crate
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

// Crate result type
pub type Result<T> = std::result::Result<T, Error>;

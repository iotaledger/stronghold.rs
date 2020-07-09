// Vault is an in-memory database format which is designed to work
// without a central server.

// the format of this databse is based off of ordered data chains.

// A Chain start with an `InitCommit`.  Changes to the data is represented
// as a descendent of the InitCommit. The data also features a counter field.
// Any commit that isn't a descendent of the InitCommit is ignored.

use thiserror::Error as DeriveError;

mod base64;
mod crypt_box;
mod types;
mod vault;

pub use crate::{
    base64::{Base64Decodable, Base64Encodable},
    crypt_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        utils::{Id, IndexHint},
        AsView, AsViewMut, DataCommit, SealedCommit, SealedPayload,
    },
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

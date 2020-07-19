/// Vault is an in-memory database specification which is designed to work
/// without a central server. The data in the database follows a versioned format
/// where each user can access a chain of data that documents changes to a group or piece of related data.  Only
/// the user which holds the associated id and key may modify the data in a chain.
///
/// Every Data chain starts with an `InitTransaction`.  The `InitTransaction` contains the user's designated id,
/// some metadata and no sealed data. Any proceeding data on the same chain needs to be a descendent of this
/// original record or else it is considered invalid.  
///
/// Data can be added to the chain via a `DataTransaction`.  The `DataTransaction` is associated to the chain
/// through the owner's ID and it also contains its own randomly generated ID.  As with every other record, a
/// `DataTransaction` also contain a Counter which allows the Vault to identify which record is the latest in the
/// chain. The counter also helps with determining the order of transactions made to the data in a chain.
///
/// Records may also be revoked from the Vault through a `RevocationTransaction`. A `RevocationTransaction` is
/// created and it references the id of a existing `DataTransaction`. The `RevocationTransaction` stages the
/// associated record for deletion. The record is deleted when the chain preforms a garbage collection and the
/// `RevocationTransaction` is deleted along with it.
use thiserror::Error as DeriveError;

mod base64;
mod crypto_box;
mod types;
mod vault;

pub use crate::{
    base64::{Base64Decodable, Base64Encodable},
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::utils::{Id, RecordHint},
    vault::{DBReader, DBView, DBWriter, DeleteRequest, ListResult, ReadRequest, ReadResult, Record, WriteRequest},
};

/// Errors for the Vault Crate
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

pub use primitives;
use thiserror::Error as DeriveError;

mod chacha_ietf;
mod chachapoly;
#[macro_use]
mod internal;
mod poly;
#[macro_use]
mod verify;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Invalid Data")]
    InvalidData,
    #[error("Interface Error occuring")]
    InterfaceError,
    #[error("Error: `{0}`")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

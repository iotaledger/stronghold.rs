pub use primitives;
use thiserror::Error as DeriveError;

#[macro_use]
mod internal;
#[macro_use]
mod verify;

mod chacha_ietf;
mod chachapoly;
mod poly;
mod xchacha;

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

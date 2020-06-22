use thiserror::Error as DeriveError;

#[macro_use]
mod internal;
#[macro_use]
mod verify;

mod chacha_ietf;
mod chachapoly;
mod chachapoly_ietf;
mod poly;
mod xchacha;
mod xchachapoly;

pub use crate::{
    chacha_ietf::ChaCha20Ietf, chachapoly_ietf::ChachaPolyIetf, poly::Poly1305, xchacha::XChaCha20,
    xchachapoly::XChaChaPoly,
};
pub use primitives;

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

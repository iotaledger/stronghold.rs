#![cfg_attr(feature = "cargo-clippy", allow(clippy::reversed_empty_ranges))]

/// This crate implements five different cryptographically secure cipher algorithms:
/// - Poly1305
/// - ChaCha20
/// - XChaCha20
/// - ChaCha20-Poly1305
/// - XChaCha20-Poly1305
///
/// The internals of these algorithms are defined using macros to make them compose with one another.
///
use thiserror::Error as DeriveError;

#[macro_use]
mod internal;
#[macro_use]
mod verify;

mod chacha_ietf;
mod chachapoly_ietf;
mod poly;
mod xchacha;
mod xchachapoly;

pub use crate::{
    chacha_ietf::ChaCha20Ietf, chachapoly_ietf::ChaChaPolyIetf, poly::Poly1305, xchacha::XChaCha20,
    xchachapoly::XChaChaPoly,
};
pub use primitives;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Invalid Data")]
    InvalidData,
    #[error("Crypto Interface Error")]
    InterfaceError,
    #[error("Error: `{0}`")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

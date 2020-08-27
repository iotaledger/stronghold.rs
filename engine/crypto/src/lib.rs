// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

#![cfg_attr(feature = "cargo-clippy", allow(clippy::reversed_empty_ranges))]

/// This crate implements five different cryptographically secure cipher algorithms:
/// - Poly1305
/// - ChaCha20
/// - XChaCha20
/// - ChaCha20-Poly1305
/// - XChaCha20-Poly1305
///
/// The internals of these algorithms are defined using macros to make them compose with one another. The
/// algorithms were tested against libsodium's algorithms to verify their integrity.
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

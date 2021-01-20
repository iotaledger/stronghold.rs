// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

mod traits;
pub use traits::*;

pub mod AES;
pub mod X25519XChacha20Poly1305;

use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug, PartialEq)]
pub enum Error {
    #[error("{reason:?}")]
    ViewError { reason: &'static str },
    #[error("{0:?}")]
    RuntimeError(runtime::Error),
    #[error("{0:?}")]
    CryptoError(crypto::Error),
}

pub type Result<A> = std::result::Result<A, Error>;

impl Error {
    fn view(reason: &'static str) -> Error {
        Error::ViewError { reason }
    }
}

impl From<runtime::Error> for Error {
    fn from(e: runtime::Error) -> Self {
        Error::RuntimeError(e)
    }
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::CryptoError(e)
    }
}

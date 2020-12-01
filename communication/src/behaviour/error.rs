// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum QueryError {
    #[error("Transport error: `{0}`")]
    TransportError(String),

    #[error("Noise authentic error: `{0}")]
    NoiseAuthenticError(String),

    #[error("Connection error: `{0}`")]
    ConnectionError(String),

    #[error("IO error: `{0}`")]
    IOError(String),

    #[error("Missing response channel: `{0}`")]
    MissingChannelError(String),
}

pub type QueryResult<T> = std::result::Result<T, QueryError>;

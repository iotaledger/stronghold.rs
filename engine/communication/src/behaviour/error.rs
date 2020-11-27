// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum QueryError {
    #[error("Connection Error: `{0}`")]
    ConnectionError(String),

    #[error("IO Error: `{0}`")]
    IOError(String),

    #[error("Missing Channel for Request: `{0}`")]
    MissingChannelError(String),
}

pub type QueryResult<T> = std::result::Result<T, QueryError>;

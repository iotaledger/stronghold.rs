// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as DeriveError;

#[derive(Debug, DeriveError)]
pub enum QueryError {
    #[error("Mailbox Error: `{0}`")]
    Mailbox(String),

    #[error("Connection Error: `{0}`")]
    ConnectionError(String),

    #[error("Kademlia Error: `{0}`")]
    KademliaError(String),

    #[error("Proto-buf Error: `{0}`")]
    ProtoBufError(String),

    #[error("IO Error: `{0}`")]
    IOError(String),

    #[error("Missing Channel for Request: `{0}`")]
    MissingChannelError(String),
}

pub type QueryResult<T> = std::result::Result<T, QueryError>;

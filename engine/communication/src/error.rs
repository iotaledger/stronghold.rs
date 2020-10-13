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
}

pub type QueryResult<T> = std::result::Result<T, QueryError>;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Ping,
    Publish(MailboxRecord),
    Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    key: String,
    value: String,
    expires_sec: u64,
}

impl MailboxRecord {
    pub fn new(key: String, value: String, expires_sec: u64) -> Self {
        MailboxRecord {
            key,
            value,
            expires_sec,
        }
    }

    pub fn key(&self) -> String {
        self.key.clone()
    }
    pub fn value(&self) -> String {
        self.value.clone()
    }
    pub fn expires_sec(&self) -> u64 {
        self.expires_sec
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Pong,
    Result(MessageResult),
    Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageResult {
    Success,
    Error,
}

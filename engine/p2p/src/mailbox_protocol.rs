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

use crate::structs_proto as proto;
use async_trait::async_trait;
use futures::{prelude::*, AsyncRead, AsyncWrite};
use libp2p::{
    core::{
        upgrade::{read_one, write_one},
        ProtocolName,
    },
    request_response::RequestResponseCodec,
};
use prost::Message;
use std::io;

#[derive(Debug, Clone)]
pub struct MailboxProtocol();
#[derive(Clone)]
pub struct MailboxCodec();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxRequest {
    Ping,
    Publish(MailboxRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) timeout_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxResponse {
    Pong,
    Publish(MailboxResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxResult {
    Success,
    Error,
}

impl ProtocolName for MailboxProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/p2p-mailbox/1.0.0"
    }
}

#[async_trait]
impl RequestResponseCodec for MailboxCodec {
    type Protocol = MailboxProtocol;
    type Request = MailboxRequest;
    type Response = MailboxResponse;

    async fn read_request<T>(&mut self, _: &MailboxProtocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|req| match req {
                Ok(bytes) => {
                    let request = proto::Message::decode(io::Cursor::new(bytes))?;
                    proto_msg_to_req(request)
                }
                Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            })
            .await
    }

    async fn read_response<T>(&mut self, _: &MailboxProtocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|res| match res {
                Ok(bytes) => {
                    let response = proto::Message::decode(io::Cursor::new(bytes))?;
                    proto_msg_to_res(response)
                }
                Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            })
            .await
    }

    async fn write_request<T>(&mut self, _: &MailboxProtocol, io: &mut T, req: MailboxRequest) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let proto_struct = req_to_proto_msg(req);
        let mut buf = Vec::with_capacity(proto_struct.encoded_len());
        proto_struct
            .encode(&mut buf)
            .expect("Vec<u8> provides capacity as needed");
        write_one(io, buf).await
    }

    async fn write_response<T>(&mut self, _: &MailboxProtocol, io: &mut T, res: MailboxResponse) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let proto_struct = res_to_proto_msg(res);
        let mut buf = Vec::with_capacity(proto_struct.encoded_len());
        proto_struct
            .encode(&mut buf)
            .expect("Vec<u8> provides capacity as needed");
        write_one(io, buf).await
    }
}

fn proto_msg_to_req(msg: proto::Message) -> Result<MailboxRequest, io::Error> {
    let msg_type = proto::message::MessageType::from_i32(msg.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", msg.r#type)))?;
    match msg_type {
        proto::message::MessageType::Ping => Ok(MailboxRequest::Ping),
        proto::message::MessageType::Publish => {
            let proto_record = msg.record.unwrap_or_default();
            let record = MailboxRecord {
                key: String::from_utf8(proto_record.key).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                value: String::from_utf8(proto_record.value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                timeout_sec: proto_record.timeout,
            };
            Ok(MailboxRequest::Publish(record))
        }
    }
}

fn proto_msg_to_res(msg: proto::Message) -> Result<MailboxResponse, io::Error> {
    let msg_type = proto::message::MessageType::from_i32(msg.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", msg.r#type)))?;
    match msg_type {
        proto::message::MessageType::Ping => Ok(MailboxResponse::Pong),
        proto::message::MessageType::Publish => {
            match proto::message::Result::from_i32(msg.r#result)
                .ok_or_else(|| invalid_data(format!("unknown message result: {}", msg.r#result)))?
            {
                proto::message::Result::Success => Ok(MailboxResponse::Publish(MailboxResult::Success)),
                proto::message::Result::Error => Ok(MailboxResponse::Publish(MailboxResult::Error)),
            }
        }
    }
}

fn req_to_proto_msg(req: MailboxRequest) -> proto::Message {
    match req {
        MailboxRequest::Ping => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            ..proto::Message::default()
        },
        MailboxRequest::Publish(record) => {
            let proto_record = proto::Record {
                key: record.key.into_bytes(),
                value: record.value.into_bytes(),
                timeout: record.timeout_sec,
            };
            proto::Message {
                r#type: proto::message::MessageType::Publish as i32,
                record: Some(proto_record),
                ..proto::Message::default()
            }
        }
    }
}

fn res_to_proto_msg(res: MailboxResponse) -> proto::Message {
    match res {
        MailboxResponse::Pong => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            ..proto::Message::default()
        },
        MailboxResponse::Publish(r) => {
            let result = match r {
                MailboxResult::Success => proto::message::Result::Success,
                MailboxResult::Error => proto::message::Result::Error,
            };
            proto::Message {
                r#type: proto::message::MessageType::Publish as i32,
                r#result: result as i32,
                ..proto::Message::default()
            }
        }
    }
}

/// Creates an `io::Error` with `io::ErrorKind::InvalidData`.
fn invalid_data<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, e)
}

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

#[cfg(feature = "kademlia")]
use crate::message::{MailboxRecord, MessageResult};
use crate::{
    message::{Request, Response},
    structs_proto as proto,
};
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
// TODO: support no_std
use std::io::{Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind, Result as IOResult};

/// Custom protocol that extends libp2p's RequestReponseProtocol
#[derive(Debug, Clone)]
pub struct MessageProtocol();

impl ProtocolName for MessageProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/p2p-mailbox/1.0.0"
    }
}

/// Describes how messages are read from and written to the io Socket by implementing the RequestResponseCodec
#[derive(Clone)]
pub struct MessageCodec();

#[async_trait]
impl RequestResponseCodec for MessageCodec {
    type Protocol = MessageProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &MessageProtocol, io: &mut T) -> IOResult<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|req| match req {
                Ok(bytes) => {
                    let request = proto::Message::decode(IOCursor::new(bytes))?;
                    proto_msg_to_req(request)
                }
                Err(e) => Err(IOError::new(IOErrorKind::InvalidData, e)),
            })
            .await
    }

    async fn read_response<T>(&mut self, _: &MessageProtocol, io: &mut T) -> IOResult<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|res| match res {
                Ok(bytes) => {
                    let response = proto::Message::decode(IOCursor::new(bytes))?;
                    proto_msg_to_res(response)
                }
                Err(e) => Err(IOError::new(IOErrorKind::InvalidData, e)),
            })
            .await
    }

    async fn write_request<T>(&mut self, _: &MessageProtocol, io: &mut T, req: Request) -> IOResult<()>
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

    async fn write_response<T>(&mut self, _: &MessageProtocol, io: &mut T, res: Response) -> IOResult<()>
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

/// parse the message read from io into a request struct
fn proto_msg_to_req(msg: proto::Message) -> Result<Request, IOError> {
    let msg_type = proto::message::MessageType::from_i32(msg.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", msg.r#type)))?;
    match msg_type {
        proto::message::MessageType::Ping => Ok(Request::Ping),
        proto::message::MessageType::Publish => {
            let proto_record = msg.record.unwrap_or_default();
            let record = MailboxRecord::new(
                String::from_utf8(proto_record.key).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
                String::from_utf8(proto_record.value).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
                proto_record.expires,
            );
            Ok(Request::Publish(record))
        }
        proto::message::MessageType::Msg => {
            let message = String::from_utf8(msg.message).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
            Ok(Request::Message(message))
        }
    }
}

/// parse the message read from io into a response struct
fn proto_msg_to_res(msg: proto::Message) -> Result<Response, IOError> {
    let msg_type = proto::message::MessageType::from_i32(msg.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", msg.r#type)))?;
    match msg_type {
        proto::message::MessageType::Ping => Ok(Response::Pong),
        proto::message::MessageType::Publish => {
            match proto::message::Result::from_i32(msg.r#result)
                .ok_or_else(|| invalid_data(format!("unknown message result: {}", msg.r#result)))?
            {
                proto::message::Result::Success => Ok(Response::Result(MessageResult::Success)),
                proto::message::Result::Error => Ok(Response::Result(MessageResult::Error)),
            }
        }
        proto::message::MessageType::Msg => {
            let message = String::from_utf8(msg.message).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
            Ok(Response::Message(message))
        }
    }
}

/// parse the request struct into a proto::Message that can be send over a socket
fn req_to_proto_msg(req: Request) -> proto::Message {
    match req {
        Request::Ping => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            ..proto::Message::default()
        },
        Request::Publish(record) => {
            let proto_record = proto::Record {
                key: record.key().into_bytes(),
                value: record.value().into_bytes(),
                expires: record.expires_sec(),
            };
            proto::Message {
                r#type: proto::message::MessageType::Publish as i32,
                record: Some(proto_record),
                ..proto::Message::default()
            }
        }
        Request::Message(msg) => proto::Message {
            r#type: proto::message::MessageType::Msg as i32,
            message: msg.into_bytes(),
            ..proto::Message::default()
        },
    }
}

/// parse the response struct into a proto::Message that can be send over a socket
fn res_to_proto_msg(res: Response) -> proto::Message {
    match res {
        Response::Pong => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            ..proto::Message::default()
        },
        Response::Result(r) => {
            let result = match r {
                MessageResult::Success => proto::message::Result::Success,
                MessageResult::Error => proto::message::Result::Error,
            };
            proto::Message {
                r#type: proto::message::MessageType::Publish as i32,
                r#result: result as i32,
                ..proto::Message::default()
            }
        }
        Response::Message(msg) => proto::Message {
            r#type: proto::message::MessageType::Msg as i32,
            message: msg.into_bytes(),
            ..proto::Message::default()
        },
    }
}

/// Creates an `IOError` with `IOErrorKind::InvalidData`.
fn invalid_data<E>(e: E) -> IOError
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    IOError::new(IOErrorKind::InvalidData, e)
}

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::structs_proto as proto;
use crate::message::{MailboxRecord, Request, RequestOutcome, Response};
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
        proto::message::MessageType::PutRecord => {
            let proto_record = msg.record.unwrap_or_default();
            let record = MailboxRecord::new(
                String::from_utf8(proto_record.key).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
                String::from_utf8(proto_record.value).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
            );
            Ok(Request::PutRecord(record))
        }
        proto::message::MessageType::GetRecord => {
            let key = String::from_utf8(msg.key).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
            Ok(Request::GetRecord(key))
        }
    }
}

/// parse the message read from io into a response struct
fn proto_msg_to_res(msg: proto::Message) -> Result<Response, IOError> {
    let msg_type = proto::message::MessageType::from_i32(msg.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", msg.r#type)))?;
    match msg_type {
        proto::message::MessageType::Ping => Ok(Response::Pong),
        proto::message::MessageType::PutRecord => {
            match proto::message::Outcome::from_i32(msg.r#outcome)
                .ok_or_else(|| invalid_data(format!("unknown message result: {}", msg.r#outcome)))?
            {
                proto::message::Outcome::Success => Ok(Response::Outcome(RequestOutcome::Success)),
                proto::message::Outcome::Error => Ok(Response::Outcome(RequestOutcome::Error)),
            }
        }
        proto::message::MessageType::GetRecord => {
            let proto_record = msg.record.unwrap_or_default();
            let record = MailboxRecord::new(
                String::from_utf8(proto_record.key).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
                String::from_utf8(proto_record.value).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?,
            );
            Ok(Response::Record(record))
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
        Request::PutRecord(record) => {
            let proto_record = proto::Record {
                key: record.key().into_bytes(),
                value: record.value().into_bytes(),
            };
            proto::Message {
                r#type: proto::message::MessageType::PutRecord as i32,
                record: Some(proto_record),
                ..proto::Message::default()
            }
        }
        Request::GetRecord(key) => proto::Message {
            r#type: proto::message::MessageType::GetRecord as i32,
            key: key.into_bytes(),
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
        Response::Outcome(o) => {
            let outcome = match o {
                RequestOutcome::Success => proto::message::Outcome::Success,
                RequestOutcome::Error => proto::message::Outcome::Error,
            };
            proto::Message {
                r#type: proto::message::MessageType::PutRecord as i32,
                r#outcome: outcome as i32,
                ..proto::Message::default()
            }
        }
        Response::Record(record) => {
            let proto_record = proto::Record {
                key: record.key().into_bytes(),
                value: record.value().into_bytes(),
            };
            proto::Message {
                r#type: proto::message::MessageType::GetRecord as i32,
                record: Some(proto_record),
                ..proto::Message::default()
            }
        }
    }
}

/// Creates an `IOError` with `IOErrorKind::InvalidData`.
fn invalid_data<E>(e: E) -> IOError
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    IOError::new(IOErrorKind::InvalidData, e)
}

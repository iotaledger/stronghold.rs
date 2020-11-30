// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use core::{fmt::Debug, marker::PhantomData};
use futures::{prelude::*, AsyncRead, AsyncWrite};
use libp2p::{
    core::{
        upgrade::{read_one, write_one},
        ProtocolName,
    },
    request_response::RequestResponseCodec,
};
use serde::{de::DeserializeOwned, Serialize};
// TODO: support no_std
use std::io::{Error as IOError, ErrorKind as IOErrorKind, Result as IOResult};

/// Trait for the generic Request and Response types
pub trait MessageEvent: Serialize + DeserializeOwned + Debug + Send + Clone + Sync + 'static {}
impl<T: Serialize + DeserializeOwned + Debug + Send + Clone + Sync + 'static> MessageEvent for T {}

/// Custom protocol that extends libp2p's RequestReponseProtocol
#[derive(Debug, Clone)]
pub struct MessageProtocol();

impl ProtocolName for MessageProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/stronghold-communication/1.0.0"
    }
}

/// Describes how messages are read from and written to the io Socket by implementing the RequestResponseCodec
#[derive(Clone)]
pub struct MessageCodec<T, U> {
    p: PhantomData<T>,
    q: PhantomData<U>,
}

impl<T, U> MessageCodec<T, U> {
    pub fn new(p: PhantomData<T>, q: PhantomData<U>) -> Self {
        MessageCodec { p, q }
    }
}

/// Read and write request and responses and parse them into the generic structs T and U
#[async_trait]
impl<T, U> RequestResponseCodec for MessageCodec<T, U>
where
    T: MessageEvent,
    U: MessageEvent,
{
    type Protocol = MessageProtocol;
    type Request = T;
    type Response = U;

    // read requests from remote peers and parse them into the request struct
    async fn read_request<R>(&mut self, _: &MessageProtocol, io: &mut R) -> IOResult<Self::Request>
    where
        R: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|req| match req {
                Ok(bytes) => {
                    serde_json::from_slice(bytes.as_slice()).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))
                }
                Err(e) => Err(IOError::new(IOErrorKind::InvalidData, e)),
            })
            .await
    }

    // read responses from remote peers and parse them into the request struct
    async fn read_response<R>(&mut self, _: &MessageProtocol, io: &mut R) -> IOResult<Self::Response>
    where
        R: AsyncRead + Unpin + Send,
    {
        read_one(io, 1024)
            .map(|res| match res {
                Ok(bytes) => {
                    serde_json::from_slice(bytes.as_slice()).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))
                }
                Err(e) => Err(IOError::new(IOErrorKind::InvalidData, e)),
            })
            .await
    }

    // deserialize request and write to the io socket
    async fn write_request<R>(&mut self, _: &MessageProtocol, io: &mut R, req: Self::Request) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&req).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }

    //  deserialize response and write to the io socket
    async fn write_response<R>(&mut self, _: &MessageProtocol, io: &mut R, res: Self::Response) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&res).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use async_std::{
        io,
        net::{TcpListener, TcpStream},
        task,
    };
    use serde::Deserialize;

    type RequestId = u64;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Message {
        id: RequestId,
        msg: String,
        record: Option<Record>,
        message_type: Type,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Record {
        key: String,
        values: Vec<String>,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    enum Type {
        Request,
        Response(RequestId),
    }

    #[test]
    fn send_request() {
        let listener = task::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer = task::spawn(async {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Message, Message>::new(PhantomData, PhantomData);
            let mut socket = TcpStream::connect("127.0.0.1:8080").await.unwrap();
            let record = Record {
                key: "key1".to_string(),
                values: vec!["value1".to_string(), "value2".to_string()],
            };
            let message = Message {
                id: 1u64,
                msg: "POST/record".to_string(),
                record: Some(record),
                message_type: Type::Request,
            };
            codec
                .write_request(&protocol, &mut socket, message.clone())
                .await
                .unwrap();
            let received = codec.read_request(&protocol, &mut socket).await.unwrap();
            assert_eq!(message, received);
        });
        task::block_on(async {
            listener.await;
            writer.await;
        })
    }

    #[test]
    fn send_response() {
        let listener = task::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8081").await.unwrap();
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer = task::spawn(async {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Message, Message>::new(PhantomData, PhantomData);
            let mut socket = TcpStream::connect("127.0.0.1:8081").await.unwrap();
            let message = Message {
                id: 2u64,
                msg: "OK".to_string(),
                record: None,
                message_type: Type::Response(1u64),
            };
            codec
                .write_response(&protocol, &mut socket, message.clone())
                .await
                .unwrap();
            let received = codec.read_response(&protocol, &mut socket).await.unwrap();
            assert_eq!(message, received);
        });
        task::block_on(async {
            listener.await;
            writer.await;
        })
    }
}

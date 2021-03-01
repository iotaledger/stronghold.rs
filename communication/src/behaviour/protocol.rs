// Copyright 2020-2021 IOTA Stiftung
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

/// Custom protocol that extends libp2ps RequestResponseProtocol
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

impl<T, U> Default for MessageCodec<T, U> {
    fn default() -> Self {
        MessageCodec {
            p: PhantomData,
            q: PhantomData,
        }
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
        read_one(io, usize::MAX)
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
        read_one(io, usize::MAX)
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
        net::{Shutdown, TcpListener, TcpStream},
        task,
    };
    use stronghold_utils::test_utils;

    #[test]
    fn send_request() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let listener = task::block_on(async { TcpListener::bind("127.0.0.1:8081").await.unwrap() });
        let listener_handle = task::spawn(async move {
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect("127.0.0.1:8081").await.unwrap();
            for bytes in test_vector.iter() {
                codec
                    .write_request(&protocol, &mut socket, bytes.clone())
                    .await
                    .unwrap();
            }
            for bytes in test_vector.iter() {
                let received = codec.read_request(&protocol, &mut socket).await.unwrap();
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).unwrap();
        });
        task::block_on(async {
            future::join(listener_handle, writer_handle).await;
        });
    }

    #[test]
    fn send_response() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let listener = task::block_on(async { TcpListener::bind("127.0.0.1:8082").await.unwrap() });
        let listener_handle = task::spawn(async move {
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect("127.0.0.1:8082").await.unwrap();
            for bytes in test_vector.iter() {
                codec
                    .write_response(&protocol, &mut socket, bytes.clone())
                    .await
                    .unwrap();
            }
            for bytes in test_vector.iter() {
                let received = codec.read_response(&protocol, &mut socket).await.unwrap();
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).unwrap();
        });
        task::block_on(async {
            future::join(listener_handle, writer_handle).await;
        });
    }

    #[test]
    #[should_panic]
    fn corrupt_request() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let listener = task::block_on(async { TcpListener::bind("127.0.0.1:8083").await.unwrap() });
        let listener_handle = task::spawn(async move {
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect("127.0.0.1:8083").await.unwrap();
            for bytes in test_vector.clone().iter_mut() {
                test_utils::corrupt(bytes);
                codec
                    .write_request(&protocol, &mut socket, bytes.clone())
                    .await
                    .unwrap();
            }
            for bytes in test_vector.iter() {
                let received = codec.read_request(&protocol, &mut socket).await.unwrap();
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).unwrap();
        });
        task::block_on(async {
            future::join(listener_handle, writer_handle).await;
        });
    }

    #[test]
    #[should_panic]
    fn corrupt_response() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let listener = task::block_on(async { TcpListener::bind("127.0.0.1:8084").await.unwrap() });
        let listener_handle = task::spawn(async move {
            let mut incoming = listener.incoming();
            let stream = incoming.next().await.unwrap().unwrap();
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer).await.unwrap();
        });

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect("127.0.0.1:8084").await.unwrap();
            for bytes in test_vector.clone().iter_mut() {
                test_utils::corrupt(bytes);
                codec
                    .write_response(&protocol, &mut socket, bytes.clone())
                    .await
                    .unwrap();
            }
            for bytes in test_vector.iter() {
                let received = codec.read_response(&protocol, &mut socket).await.unwrap();
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).unwrap();
        });
        task::block_on(async {
            future::join(listener_handle, writer_handle).await;
        });
    }
}

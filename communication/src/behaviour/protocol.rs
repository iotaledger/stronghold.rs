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
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IOResult};

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
pub struct MessageCodec<Req, Res> {
    p: PhantomData<Req>,
    q: PhantomData<Res>,
}

impl<Req, Res> Default for MessageCodec<Req, Res> {
    fn default() -> Self {
        MessageCodec {
            p: PhantomData,
            q: PhantomData,
        }
    }
}

/// Read and write requests and responses, and parse them into the generic structs Req and Res.
#[async_trait]
impl<Req, Res> RequestResponseCodec for MessageCodec<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type Protocol = MessageProtocol;
    type Request = Req;
    type Response = Res;

    // read requests from remote peers and parse them into the request struct
    async fn read_request<R>(&mut self, _: &MessageProtocol, io: &mut R) -> IOResult<Self::Request>
    where
        R: AsyncRead + Unpin + Send,
    {
        read_one(io, usize::MAX)
            .map(|req| match req {
                Ok(bytes) => {
                    serde_json::from_slice(bytes.as_slice()).map_err(|e| IoError::new(IoErrorKind::InvalidData, e))
                }
                Err(e) => Err(IoError::new(IoErrorKind::InvalidData, e)),
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
                    serde_json::from_slice(bytes.as_slice()).map_err(|e| IoError::new(IoErrorKind::InvalidData, e))
                }
                Err(e) => Err(IoError::new(IoErrorKind::InvalidData, e)),
            })
            .await
    }

    // deserialize request and write to the io socket
    async fn write_request<R>(&mut self, _: &MessageProtocol, io: &mut R, req: Self::Request) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&req).map_err(|e| IoError::new(IoErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }

    //  deserialize response and write to the io socket
    async fn write_response<R>(&mut self, _: &MessageProtocol, io: &mut R, res: Self::Response) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&res).map_err(|e| IoError::new(IoErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use async_std::{
        io,
        net::{Shutdown, SocketAddr, TcpListener, TcpStream},
        task,
        task::JoinHandle,
    };
    use stronghold_utils::test_utils;

    fn spawn_listener() -> (SocketAddr, JoinHandle<()>) {
        let listener = task::block_on(async {
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind tcp listener.")
        });
        let addr = listener.local_addr().expect("Faulty local address");
        let handle = task::spawn(async move {
            let mut incoming = listener.incoming();
            let stream = incoming
                .next()
                .await
                .expect("Incoming connection is none.")
                .expect("Tcp stream is none.");
            let (reader, writer) = &mut (&stream, &stream);
            io::copy(reader, writer)
                .await
                .expect("Failed to copy reader into writer.");
        });
        (addr, handle)
    }

    #[test]
    fn send_request() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let (addr, listener_handle) = spawn_listener();

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect(addr).await.expect("Failed to connect tcp stream.");
            for bytes in test_vector.iter() {
                codec
                    .write_request(&protocol, &mut socket, bytes.clone())
                    .await
                    .expect("Failed to write request.");
            }
            for bytes in test_vector.iter() {
                let received = codec
                    .read_request(&protocol, &mut socket)
                    .await
                    .expect("Failed to read request.");
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).expect("Failed to shutdown socket.");
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

        let (addr, listener_handle) = spawn_listener();

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect(addr).await.expect("Failed to connect tcp stream.");
            for bytes in test_vector.iter() {
                codec
                    .write_response(&protocol, &mut socket, bytes.clone())
                    .await
                    .expect("Failed to write response.");
            }
            for bytes in test_vector.iter() {
                let received = codec
                    .read_response(&protocol, &mut socket)
                    .await
                    .expect("Failed to read response.");
                assert_eq!(bytes, &received);
            }
            socket.shutdown(Shutdown::Both).expect("Failed to shutdown socket.");
        });
        task::block_on(async {
            future::join(listener_handle, writer_handle).await;
        });
    }

    #[test]
    #[should_panic(expected = "All requests are corrupted.")]
    fn corrupt_request() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let (addr, listener_handle) = spawn_listener();

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect(addr).await.expect("Failed to connect tcp stream.");
            for bytes in test_vector.clone().iter_mut() {
                test_utils::corrupt(bytes);
                codec
                    .write_request(&protocol, &mut socket, bytes.clone())
                    .await
                    .expect("Failed to write request.");
            }
            let mut results = Vec::new();
            for bytes in test_vector.iter() {
                let received = codec
                    .read_request(&protocol, &mut socket)
                    .await
                    .expect("Failed to read request.");
                results.push(bytes == &received)
            }
            socket.shutdown(Shutdown::Both).expect("Failed to shutdown socket.");
            results.into_iter().any(|res| res)
        });
        task::block_on(async {
            let (_, results) = future::join(listener_handle, writer_handle).await;
            assert!(results, "All requests are corrupted.")
        });
    }

    #[test]
    #[should_panic(expected = "All responses are corrupted.")]
    fn corrupt_response() {
        let mut test_vector = Vec::new();
        for _ in 0..20 {
            test_vector.push(test_utils::fresh::non_empty_bytestring());
        }

        let (addr, listener_handle) = spawn_listener();

        let writer_handle = task::spawn(async move {
            let protocol = MessageProtocol();
            let mut codec = MessageCodec::<Vec<u8>, Vec<u8>>::default();
            let mut socket = TcpStream::connect(addr).await.expect("Failed to connect tcp stream.");
            for bytes in test_vector.clone().iter_mut() {
                test_utils::corrupt(bytes);
                codec
                    .write_response(&protocol, &mut socket, bytes.clone())
                    .await
                    .expect("Failed to write response.");
            }
            let mut results = Vec::new();
            for bytes in test_vector.iter() {
                let received = codec
                    .read_response(&protocol, &mut socket)
                    .await
                    .expect("Failed to read response.");
                results.push(bytes == &received)
            }
            socket.shutdown(Shutdown::Both).expect("Failed to shutdown socket.");
            results.into_iter().any(|res| res)
        });
        task::block_on(async {
            let (_, results) = future::join(listener_handle, writer_handle).await;
            assert!(results, "All responses are corrupted.")
        });
    }
}

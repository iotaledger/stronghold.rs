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

#[async_trait]
impl<T, U> RequestResponseCodec for MessageCodec<T, U>
where
    T: MessageEvent,
    U: MessageEvent,
{
    type Protocol = MessageProtocol;
    type Request = T;
    type Response = U;

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

    async fn write_request<R>(&mut self, _: &MessageProtocol, io: &mut R, req: Self::Request) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&req).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }

    async fn write_response<R>(&mut self, _: &MessageProtocol, io: &mut R, res: Self::Response) -> IOResult<()>
    where
        R: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&res).map_err(|e| IOError::new(IOErrorKind::InvalidData, e))?;
        write_one(io, buf).await
    }
}

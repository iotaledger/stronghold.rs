// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

use crate::{behaviour::MessageEvent, Request};
use futures::{channel::oneshot, future::BoxFuture, prelude::*};
use libp2p::{
    core::{
        upgrade::{read_one, write_one, InboundUpgrade, OutboundUpgrade, ReadOneError, UpgradeInfo},
        ProtocolName,
    },
    swarm::NegotiatedSubstream,
};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::SmallVec;
use std::{fmt::Debug, io, marker::PhantomData};

#[derive(Debug, Clone)]
pub struct MessageProtocol;

impl ProtocolName for MessageProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/stronghold-communication/1.0.0"
    }
}

#[derive(Debug, Clone)]
pub enum ProtocolSupport {
    Inbound,
    Outbound,
    Full,
}

impl ProtocolSupport {
    pub fn inbound(&self) -> bool {
        match self {
            ProtocolSupport::Inbound | ProtocolSupport::Full => true,
            ProtocolSupport::Outbound => false,
        }
    }

    pub fn outbound(&self) -> bool {
        match self {
            ProtocolSupport::Outbound | ProtocolSupport::Full => true,
            ProtocolSupport::Inbound => false,
        }
    }
}

#[derive(Debug)]
pub struct ResponseProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub(crate) protocols: SmallVec<[MessageProtocol; 2]>,
    pub(crate) request_sender: oneshot::Sender<Req>,
    pub(crate) response_receiver: oneshot::Receiver<Res>,
}

impl<Req, Res> UpgradeInfo for ResponseProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type Info = MessageProtocol;
    type InfoIter = smallvec::IntoIter<[Self::Info; 2]>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl<Req, Res> InboundUpgrade<NegotiatedSubstream> for ResponseProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type Output = bool;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, mut io: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {
            let request = read_and_parse(&mut io).await?;
            let _ = self.request_sender.send(request);

            let res = match self.response_receiver.await {
                Ok(response) => parse_and_write(&mut io, response).await.map(|_| true)?,
                Err(_) => io.close().await.map(|_| false)?,
            };
            Ok(res)
        }
        .boxed()
    }
}

#[derive(Debug)]
pub struct RequestProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    pub(crate) protocols: SmallVec<[MessageProtocol; 2]>,
    pub(crate) request: Request<Req, Res>,
    pub(crate) marker: PhantomData<Res>,
}

impl<Req, Res> UpgradeInfo for RequestProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type Info = MessageProtocol;
    type InfoIter = smallvec::IntoIter<[Self::Info; 2]>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl<Req, Res> OutboundUpgrade<NegotiatedSubstream> for RequestProtocol<Req, Res>
where
    Req: MessageEvent,
    Res: MessageEvent,
{
    type Output = bool;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, mut io: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {
            parse_and_write(&mut io, self.request.message).await?;
            let response = read_and_parse(&mut io).await?;
            let sent_response = self.request.response_sender.send(response);
            Ok(sent_response.is_ok())
        }
        .boxed()
    }
}

async fn read_and_parse<T: DeserializeOwned>(io: &mut NegotiatedSubstream) -> Result<T, io::Error> {
    read_one(io, usize::MAX)
        .map(|res| match res {
            Ok(bytes) => {
                serde_json::from_slice(bytes.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
            Err(ReadOneError::Io(io_err)) => Err(io_err),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
        .await
}

async fn parse_and_write<T: Serialize>(io: &mut NegotiatedSubstream, data: T) -> Result<(), io::Error> {
    let buf = serde_json::to_vec(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_one(io, buf).await?;
    io.close().await
}

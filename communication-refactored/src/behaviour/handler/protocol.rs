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

use crate::RqRsMessage;
use futures::{channel::oneshot, future::BoxFuture, prelude::*};
use libp2p::{
    core::{
        upgrade::{read_length_prefixed, write_length_prefixed, InboundUpgrade, OutboundUpgrade, UpgradeInfo},
        ProtocolName,
    },
    swarm::NegotiatedSubstream,
};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::SmallVec;
use std::{fmt::Debug, io, marker::PhantomData};

/// Protocol Name.
/// A Request-Response messages will only be successful if both peers support the [`CommunicationProtocol`].
#[derive(Debug, Clone)]
pub struct CommunicationProtocol {
    version: String,
}

impl CommunicationProtocol {
    pub fn new_version(major: u8, minor: u8, patch: u8) -> Self {
        let version = format!("/stronghold-communication/{}.{}.{}", major, minor, patch);
        CommunicationProtocol { version }
    }
}

impl ProtocolName for CommunicationProtocol {
    fn protocol_name(&self) -> &[u8] {
        self.version.as_bytes()
    }
}

/// Response substream upgrade protocol.
///
/// Receives a request and sends a response.
#[derive(Debug)]
pub struct ResponseProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    // Supported protocols for inbound requests.
    // Rejects all inbound requests if empty.
    pub(crate) protocols: SmallVec<[CommunicationProtocol; 2]>,
    // Channel for forwarding the inbound request.
    pub(crate) request_tx: oneshot::Sender<(Rq, oneshot::Sender<Rs>)>,
}

impl<Rq, Rs> UpgradeInfo for ResponseProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    type Info = CommunicationProtocol;
    type InfoIter = smallvec::IntoIter<[Self::Info; 2]>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl<Rq, Rs> InboundUpgrade<NegotiatedSubstream> for ResponseProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    // If a response was send back to remote.
    // False if the response channel was dropped on a higher level before a response was sent.
    type Output = bool;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, mut io: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {
            // Read a request form the substream, forward it to the handler.
            let request = read_and_parse(&mut io).await?;
            // Create channel to receive the response.
            let (tx, rx) = oneshot::channel();
            let _ = self.request_tx.send((request, tx));

            // Receive the response, write it back to the substream.
            let res = match rx.await {
                Ok(response) => parse_and_write(&mut io, &response).await.map(|_| true)?,
                Err(_) => false,
            };
            io.close().await?;
            Ok(res)
        }
        .boxed()
    }
}

/// Request substream upgrade protocol.
///
/// Sends a request and receives a response.
#[derive(Debug)]
pub struct RequestProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    // Supported protocols for outbound requests.
    // Rejects all outbound requests if empty.
    pub(crate) protocols: SmallVec<[CommunicationProtocol; 2]>,
    // Outbound request.
    pub(crate) request: Rq,

    pub _marker: PhantomData<Rs>,
}

impl<Rq, Rs> UpgradeInfo for RequestProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    type Info = CommunicationProtocol;
    type InfoIter = smallvec::IntoIter<[Self::Info; 2]>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl<Rq, Rs> OutboundUpgrade<NegotiatedSubstream> for RequestProtocol<Rq, Rs>
where
    Rq: RqRsMessage + Clone,
    Rs: RqRsMessage,
{
    // Response from the remote for the sent request.
    type Output = Rs;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, mut io: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {
            // Write outbound request to the substream.
            parse_and_write(&mut io, &self.request).await?;
            // Read inbound response and return it.
            let response = read_and_parse(&mut io).await?;
            io.close().await?;
            Ok(response)
        }
        .boxed()
    }
}

// Read from substream and deserialize the received bytes.
async fn read_and_parse<T: DeserializeOwned>(io: &mut NegotiatedSubstream) -> Result<T, io::Error> {
    read_length_prefixed(io, usize::MAX)
        .map(|res| match res {
            Ok(bytes) => {
                serde_json::from_slice(bytes.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
        .await
}

// Serialize the data and write bytes to substream.
async fn parse_and_write<T: Serialize>(io: &mut NegotiatedSubstream, data: &T) -> Result<(), io::Error> {
    let buf = serde_json::to_vec(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_length_prefixed(io, buf).await
}

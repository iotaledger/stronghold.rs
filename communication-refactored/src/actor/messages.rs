// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::{
    firewall::{Rule, RuleDirection},
    ListenErr, OutboundFailure,
};
use actix::Message;
use libp2p::{Multiaddr, PeerId};

#[derive(Message)]
#[rtype(result = "Result<Rs, OutboundFailure>")]
pub struct SendRequest<Rq, Rs: 'static> {
    pub peer: PeerId,
    pub request: Rq,
    _marker: PhantomData<Rs>,
}

impl<Rq, Rs: 'static> SendRequest<Rq, Rs> {
    pub fn new(peer: PeerId, request: Rq) -> Self {
        SendRequest {
            peer,
            request,
            _marker: PhantomData,
        }
    }
}

#[derive(Message)]
#[rtype(result = "Result<Multiaddr, ListenErr>")]
pub struct StartListening {
    pub address: Option<Multiaddr>,
}

#[derive(Message)]
#[rtype(result = "PeerId")]
pub struct GetLocalPeerId;

#[derive(Message)]
#[rtype(result = "()")]
pub struct AddPeerAddr {
    pub peer: PeerId,
    pub address: Multiaddr,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct SetFirewallRule<TRq> {
    pub peer: PeerId,
    pub direction: RuleDirection,
    pub rule: Rule<TRq>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct SetFirewallDefault<TRq> {
    pub direction: RuleDirection,
    pub rule: Rule<TRq>,
}

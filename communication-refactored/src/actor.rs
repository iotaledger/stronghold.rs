// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "actor")]

pub mod messages;
use crate::{ListenErr, Multiaddr, OutboundFailure, PeerId, ReceiveRequest, RqRsMessage, ShCommunication};
use actix::{dev::ToEnvelope, prelude::*};
use futures::{channel::mpsc, FutureExt, TryFutureExt};
use messages::*;
use std::{io, marker::PhantomData};

pub struct GetClient<Rq: Message, C: Actor + Handler<Rq>> {
    pub remote: PeerId,
    _marker: (PhantomData<C>, PhantomData<Rq>),
}

impl<Rq: Message, C: Actor + Handler<Rq>> Message for GetClient<Rq, C> {
    type Result = Addr<C>;
}

pub struct CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    comms: ShCommunication<Rq, Rs>,
    inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<Rq, Rs>>>,
    registry: Addr<ARegistry>,
    _marker: PhantomData<C>,
}

impl<ARegistry, C, Rq, Rs> CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    #[cfg(feature = "tcp-transport")]
    pub async fn new(registry: Addr<ARegistry>) -> Result<Self, io::Error> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (inbound_request_tx, inbound_request_rx) = mpsc::channel(1);
        let comms = ShCommunication::new(firewall_tx, inbound_request_tx, None).await?;
        let actor = Self {
            comms,
            inbound_request_rx: Some(inbound_request_rx),
            registry,
            _marker: PhantomData,
        };
        Ok(actor)
    }
}

impl<ARegistry, C, Rq, Rs> Actor for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let inbound_request_rx = self.inbound_request_rx.take().unwrap();
        Self::add_stream(inbound_request_rx, ctx);
    }
}

impl<ARegistry, C, Rq, Rs> Handler<SendRequest<Rq, Rs>> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = ResponseActFuture<Self, Result<Rs, OutboundFailure>>;

    fn handle(&mut self, msg: SendRequest<Rq, Rs>, _ctx: &mut Context<Self>) -> Self::Result {
        let mut comms = self.comms.clone();
        async move { comms.send_request(msg.peer, msg.request).await }
            .into_actor(self)
            .boxed_local()
    }
}

impl<ARegistry, C, Rq, Rs> Handler<StartListening> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = ResponseActFuture<Self, Result<Multiaddr, ListenErr>>;

    fn handle(&mut self, msg: StartListening, _ctx: &mut Context<Self>) -> Self::Result {
        let mut comms = self.comms.clone();
        let future = async move { comms.start_listening(msg.address).await };
        future.into_actor(self).boxed_local()
    }
}

impl<ARegistry, C, Rq, Rs> Handler<GetLocalPeerId> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = MessageResult<GetLocalPeerId>;

    fn handle(&mut self, _: GetLocalPeerId, _ctx: &mut Context<Self>) -> Self::Result {
        MessageResult(self.comms.get_peer_id())
    }
}

impl<ARegistry, C, Rq, Rs> Handler<AddPeerAddr> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: AddPeerAddr, _ctx: &mut Context<Self>) -> Self::Result {
        let mut comms = self.comms.clone();
        let future = async move { comms.add_address(msg.peer, msg.address).await };
        future.into_actor(self).boxed_local()
    }
}

impl<ARegistry, C, Rq, Rs> Handler<SetFirewallRule<Rq>> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: SetFirewallRule<Rq>, _ctx: &mut Context<Self>) -> Self::Result {
        let mut comms = self.comms.clone();
        let future = async move { comms.set_peer_rule(msg.peer, msg.direction, msg.rule).await };
        future.into_actor(self).boxed_local()
    }
}

impl<ARegistry, C, Rq, Rs> Handler<SetFirewallDefault<Rq>> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: SetFirewallDefault<Rq>, _ctx: &mut Context<Self>) -> Self::Result {
        let mut comms = self.comms.clone();
        let future = async move { comms.set_firewall_default(msg.direction, msg.rule).await };
        future.into_actor(self).boxed_local()
    }
}

impl<ARegistry, C, Rq, Rs> StreamHandler<ReceiveRequest<Rq, Rs>> for CommunicationActor<ARegistry, C, Rq, Rs>
where
    ARegistry: Actor + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Clone + Message<Result = Rs> + RqRsMessage,
    Rs: Clone + RqRsMessage,
{
    fn handle(&mut self, item: ReceiveRequest<Rq, Rs>, ctx: &mut Self::Context) {
        let ReceiveRequest {
            request,
            response_tx,
            peer,
            ..
        } = item;

        let fut = self
            .registry
            .send(GetClient {
                remote: peer,
                _marker: (PhantomData, PhantomData),
            })
            .and_then(|client| client.send(request))
            .map_ok(|response| response_tx.send(response))
            .map(|_| ())
            .into_actor(self);
        ctx.wait(fut);
    }
}

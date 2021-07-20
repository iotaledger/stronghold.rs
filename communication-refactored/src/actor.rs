// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod messages;
use crate::{ListenErr, Multiaddr, OutboundFailure, PeerId, ReceiveRequest, RqRsMessage, ShCommunication};
use actix::{dev::ToEnvelope, prelude::*};
use futures::{channel::mpsc, FutureExt, TryFutureExt};
use messages::*;
use std::{borrow::Borrow, io, marker::PhantomData};

#[macro_use]
macro_rules! impl_handler {
    ($mty:ty => $rty:ty, |$cid:ident, $mid:ident| $($body:stmt)+ ) => {
        impl<ARegistry, C, Rq, Rs, TRq> Handler<$mty> for CommunicationActor<ARegistry, C, Rq, Rs, TRq>
        where
            ARegistry: ArbiterService + Handler<GetClient<Rq, C>>,
            ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
            C: Actor + Handler<Rq> + Send,
            C::Context: ToEnvelope<C, Rq>,
            Rq: Message<Result = Rs> + RqRsMessage + Borrow<TRq> + Clone,
            Rs: RqRsMessage + Clone,
            TRq: Clone + Send + 'static,
        {
            type Result = ResponseActFuture<Self, $rty>;
            fn handle(&mut self, $mid: $mty, _: &mut Self::Context) -> Self::Result {
                let mut $cid = self.comms.clone();
                async move { $($body)+ }.into_actor(self).boxed_local()
            }
        }
    };
}

#[derive(Message)]
#[rtype(result = "Addr<C>")]
pub struct GetClient<Rq: Message, C: Actor + Handler<Rq>> {
    pub remote: PeerId,
    _marker: (PhantomData<C>, PhantomData<Rq>),
}

pub struct CommunicationActor<ARegistry, C, Rq, Rs, TRq = Rq>
where
    ARegistry: Actor,
    Rq: Message + RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    comms: ShCommunication<Rq, Rs, TRq>,
    inbound_request_rx: Option<mpsc::Receiver<ReceiveRequest<Rq, Rs>>>,
    _marker: (PhantomData<ARegistry>, PhantomData<C>),
}

impl<ARegistry, C, Rq, Rs, TRq> CommunicationActor<ARegistry, C, Rq, Rs, TRq>
where
    ARegistry: Actor,
    Rq: Message + RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    #[cfg(feature = "tcp-transport")]
    pub async fn new() -> Result<Self, io::Error> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (inbound_request_tx, inbound_request_rx) = mpsc::channel(1);
        let comms = ShCommunication::new(firewall_tx, inbound_request_tx, None).await?;
        let actor = Self {
            comms,
            inbound_request_rx: Some(inbound_request_rx),
            _marker: (PhantomData, PhantomData),
        };
        Ok(actor)
    }
}

impl<ARegistry, C, Rq, Rs, TRq> Actor for CommunicationActor<ARegistry, C, Rq, Rs, TRq>
where
    ARegistry: ArbiterService + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Message<Result = Rs> + RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let inbound_request_rx = self.inbound_request_rx.take().unwrap();
        Self::add_stream(inbound_request_rx, ctx);
    }
}

impl<ARegistry, C, Rq, Rs, TRq> StreamHandler<ReceiveRequest<Rq, Rs>> for CommunicationActor<ARegistry, C, Rq, Rs, TRq>
where
    ARegistry: ArbiterService + Handler<GetClient<Rq, C>>,
    ARegistry::Context: ToEnvelope<ARegistry, GetClient<Rq, C>>,
    C: Actor + Handler<Rq> + Send,
    C::Context: ToEnvelope<C, Rq>,
    Rq: Message<Result = Rs> + RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    fn handle(&mut self, item: ReceiveRequest<Rq, Rs>, ctx: &mut Self::Context) {
        let ReceiveRequest {
            request,
            response_tx,
            peer,
            ..
        } = item;

        let registry = ARegistry::from_registry();
        let fut = registry
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

impl<ARegistry, C, Rq, Rs, TRq> From<(ShCommunication<Rq, Rs, TRq>, mpsc::Receiver<ReceiveRequest<Rq, Rs>>)>
    for CommunicationActor<ARegistry, C, Rq, Rs, TRq>
where
    ARegistry: Actor,
    Rq: Message + RqRsMessage + Borrow<TRq>,
    Rs: RqRsMessage,
    TRq: Clone + Send + 'static,
{
    fn from((comms, request_rx): (ShCommunication<Rq, Rs, TRq>, mpsc::Receiver<ReceiveRequest<Rq, Rs>>)) -> Self {
        Self {
            comms,
            inbound_request_rx: Some(request_rx),
            _marker: (PhantomData, PhantomData),
        }
    }
}

impl_handler!(SendRequest<Rq, Rs> => Result<Rs, OutboundFailure>, |comms, msg| {
    comms.send_request(msg.peer, msg.request).await
});

impl_handler!(StartListening => Result<Multiaddr, ListenErr>, |comms, msg| {
    let addr = msg.address.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
    comms.start_listening(addr).await
});

impl_handler!(GetLocalPeerId => PeerId, |_comms, _msg| {
    _comms.get_peer_id()
});

impl_handler!(AddPeerAddr => (), |comms, msg| {
    comms.add_address(msg.peer, msg.address).await
});

impl_handler!(SetFirewallRule<TRq> => (), |comms, msg| {
    comms.set_peer_rule(msg.peer, msg.direction, msg.rule).await
});

impl_handler!(SetFirewallDefault<TRq> => (), |comms, msg| {
    comms.set_firewall_default(msg.direction, msg.rule).await
});

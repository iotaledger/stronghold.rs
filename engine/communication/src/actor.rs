// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    behaviour::P2PNetworkBehaviour,
    message::{CommunicationEvent, ReqResEvent},
};
use async_std::task;
use core::task::{Context as TaskContext, Poll};
use futures::{channel::mpsc, future, prelude::*};
use libp2p::{core::identity::Keypair, swarm::Swarm};
use riker::actors::*;

pub enum CommActorEvent {
    Message(CommunicationEvent),
    Shutdown,
}

#[actor(CommunicationEvent)]
pub struct CommunicationActor {
    chan: ChannelRef<CommunicationEvent>,
    keypair: Keypair,
    swarm_tx: Option<mpsc::Sender<CommActorEvent>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl ActorFactoryArgs<(Keypair, ChannelRef<CommunicationEvent>)> for CommunicationActor {
    fn create_args((keypair, chan): (Keypair, ChannelRef<CommunicationEvent>)) -> Self {
        Self {
            chan,
            keypair,
            swarm_tx: None,
            poll_swarm_handle: None,
        }
    }
}

impl Actor for CommunicationActor {
    type Msg = CommunicationActorMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_outbound");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let (swarm_tx, mut swarm_rx) = mpsc::channel(16);
        self.swarm_tx = Some(swarm_tx);
        let mut swarm = P2PNetworkBehaviour::new(self.keypair.clone()).unwrap();
        P2PNetworkBehaviour::start_listening(&mut swarm, None).unwrap();
        let topic = Topic::from("swarm_inbound");
        let chan = self.chan.clone();
        let handle = ctx.run(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            loop {
                let event = match swarm_rx.poll_next_unpin(tcx) {
                    Poll::Ready(Some(event)) => event,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                };
                match event {
                    CommActorEvent::Message(message) => {
                        if let CommunicationEvent::RequestResponse {
                            peer_id,
                            request_id,
                            event,
                        } = message
                        {
                            match event {
                                ReqResEvent::Req(request) => {
                                    swarm.send_request(peer_id, request);
                                }
                                ReqResEvent::Res(response) => {
                                    swarm.send_response(response, request_id).unwrap();
                                }
                                _ => {}
                            }
                        } else if let CommunicationEvent::Identify {
                            peer_id: _,
                            public_key: _,
                            observed_addr,
                        } = message
                        {
                            Swarm::add_external_address(&mut swarm, observed_addr);
                        }
                    }
                    CommActorEvent::Shutdown => {
                        return Poll::Ready(());
                    }
                }
            }
            loop {
                match swarm.poll_next_unpin(tcx) {
                    Poll::Ready(Some(event)) => {
                        println!("Received event: {:?}", event);
                        chan.tell(
                            Publish {
                                msg: event,
                                topic: topic.clone(),
                            },
                            None,
                        )
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            Poll::Pending
        }));
        self.poll_swarm_handle = handle.ok();
    }

    fn post_stop(&mut self) {
        if let Some(tx) = self.swarm_tx.as_mut() {
            task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
                match tx.poll_ready(tcx) {
                    Poll::Ready(Ok(())) => Poll::Ready(tx.start_send(CommActorEvent::Shutdown)),
                    Poll::Ready(err) => Poll::Ready(err),
                    _ => Poll::Pending,
                }
            })).unwrap();
        }
        if let Some(handle) = self.poll_swarm_handle.as_mut() {
            task::block_on(handle);
        }
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<CommunicationEvent> for CommunicationActor {
    type Msg = CommunicationActorMsg;
    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: CommunicationEvent, _sender: Sender) {
        if let Some(tx) = self.swarm_tx.as_mut() {
            task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
                match tx.poll_ready(tcx) {
                    Poll::Ready(Ok(())) => Poll::Ready(tx.start_send(CommActorEvent::Message(msg.clone()))),
                    Poll::Ready(err) => Poll::Ready(err),
                    _ => Poll::Pending,
                }
            }))
            .unwrap();
        }
    }
}

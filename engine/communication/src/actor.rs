// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{
    message::{CommunicationEvent, P2PReqResEvent},
    MessageEvent, P2PNetworkBehaviour,
};
use async_std::task;
use core::{
    ops::Deref,
    task::{Context as TaskContext, Poll},
};
use futures::{channel::mpsc, future, prelude::*};
use libp2p::core::identity::Keypair;
use riker::actors::*;

pub enum CommActorEvent<T, U> {
    Message(CommunicationEvent<T, U>),
    Shutdown,
}

pub struct CommunicationActor<T: MessageEvent, U: MessageEvent> {
    chan: ChannelRef<CommunicationEvent<T, U>>,
    keypair: Keypair,
    swarm_tx: Option<mpsc::Sender<CommActorEvent<T, U>>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<T: MessageEvent, U: MessageEvent> ActorFactoryArgs<(Keypair, ChannelRef<CommunicationEvent<T, U>>)>
    for CommunicationActor<T, U>
{
    fn create_args((keypair, chan): (Keypair, ChannelRef<CommunicationEvent<T, U>>)) -> Self {
        Self {
            chan,
            keypair,
            swarm_tx: None,
            poll_swarm_handle: None,
        }
    }
}

impl<T: MessageEvent, U: MessageEvent> Actor for CommunicationActor<T, U> {
    type Msg = CommunicationEvent<T, U>;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_outbound");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let (swarm_tx, mut swarm_rx) = mpsc::channel(16);
        self.swarm_tx = Some(swarm_tx);
        let mut swarm = P2PNetworkBehaviour::<T, U>::new(self.keypair.clone()).unwrap();
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
                        if let CommunicationEvent::RequestResponse(boxed_event) = message {
                            match boxed_event.deref().clone() {
                                P2PReqResEvent::Req {
                                    peer_id,
                                    request_id: _,
                                    request,
                                } => {
                                    swarm.send_request(&peer_id, request);
                                }
                                P2PReqResEvent::Res {
                                    peer_id: _,
                                    request_id,
                                    response,
                                } => {
                                    swarm.send_response(response, request_id).unwrap();
                                }
                                _ => {}
                            }
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
            }))
            .unwrap();
        }
        if let Some(handle) = self.poll_swarm_handle.as_mut() {
            task::block_on(handle);
        }
    }

    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
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

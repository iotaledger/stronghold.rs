// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    behaviour::{P2PNetworkBehaviour, P2PNetworkSwarm},
    message::CommunicationEvent,
};
use async_std::task;
use core::task::{Context as TaskContext, Poll};
use futures::{future, prelude::*};
use libp2p::core::identity::Keypair;
use riker::actors::*;

#[actor(CommunicationEvent)]
struct CommunicationActor {
    swarm: P2PNetworkSwarm,
    chan: ChannelRef<CommunicationEvent>,
}

impl ActorFactoryArgs<(Keypair, ChannelRef<CommunicationEvent>)> for CommunicationActor {
    fn create_args((keypair, chan): (Keypair, ChannelRef<CommunicationEvent>)) -> Self {
        let swarm = P2PNetworkBehaviour::new(keypair).unwrap();
        Self { swarm, chan }
    }
}

impl Actor for CommunicationActor {
    type Msg = CommunicationActorMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_outbound");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
        P2PNetworkBehaviour::start_listening(&mut self.swarm, None).unwrap();
    }

    fn post_start(&mut self, _ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_inbound");
        task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            match self.swarm.poll_next_unpin(tcx) {
                Poll::Ready(Some(event)) => {
                    println!("Received event: {:?}", event);
                    self.chan.tell(
                        Publish {
                            msg: event,
                            topic: topic.clone(),
                        },
                        None,
                    )
                }
                Poll::Ready(None) => {
                    return Poll::Ready(());
                }
                Poll::Pending => {}
            }
            Poll::Pending
        }))
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<CommunicationEvent> for CommunicationActor {
    type Msg = CommunicationActorMsg;
    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: CommunicationEvent, _sender: Sender) {
        match msg {
            CommunicationEvent::RequestMessage {
                peer,
                request_id: _,
                request,
            } => {
                self.swarm.send_request(peer, request);
            }
            CommunicationEvent::ResponseMessage {
                peer: _,
                request_id,
                response,
            } => {
                self.swarm.send_response(response, request_id).unwrap();
            }
            _ => {}
        }
    }
}

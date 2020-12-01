// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use libp2p::core::identity::Keypair;
use riker::actors::*;
use serde::{Deserialize, Serialize};
use stronghold_communication::{
    actor::{CommunicationActor, CommunicationEvent},
    behaviour::message::P2PReqResEvent,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
}

struct TestActor {
    chan: ChannelRef<CommunicationEvent<Request, Response>>,
}

impl ActorFactoryArgs<ChannelRef<CommunicationEvent<Request, Response>>> for TestActor {
    fn create_args(chan: ChannelRef<CommunicationEvent<Request, Response>>) -> Self {
        TestActor { chan }
    }
}

impl Actor for TestActor {
    type Msg = CommunicationEvent<Request, Response>;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_inbound");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        println!("{}: -> got msg: {:?}", ctx.myself.name(), msg);
        if let CommunicationEvent::Message(P2PReqResEvent::Req {
            peer_id,
            request_id: Some(request_id),
            request: Request::Ping,
        }) = msg
        {
            let response = CommunicationEvent::Message(P2PReqResEvent::Res {
                peer_id,
                request_id,
                response: Response::Pong,
            });
            self.chan.tell(
                Publish {
                    msg: response,
                    topic: Topic::from("swarm_outbound"),
                },
                None,
            );
        }
    }
}

fn main() {
    let local_keys = Keypair::generate_ed25519();
    let sys = ActorSystem::new().unwrap();
    let chan: ChannelRef<CommunicationEvent<Request, Response>> = channel("remote-peer", &sys).unwrap();
    sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", (local_keys, chan.clone()))
        .unwrap();
    sys.actor_of_args::<TestActor, _>("test-actor", chan).unwrap();
    std::thread::sleep(Duration::from_secs(600));
}

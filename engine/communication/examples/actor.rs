// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication::{
    actor::CommunicationActor,
    message::{CommunicationEvent, ReqResEvent, Request, Response},
};
use core::time::Duration;
use libp2p::core::identity::Keypair;
use riker::actors::*;

#[actor(CommunicationEvent)]
struct TestActor {
    chan: ChannelRef<CommunicationEvent>,
}

impl ActorFactoryArgs<ChannelRef<CommunicationEvent>> for TestActor {
    fn create_args(chan: ChannelRef<CommunicationEvent>) -> Self {
        TestActor { chan }
    }
}

impl Actor for TestActor {
    type Msg = TestActorMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("swarm_inbound");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<CommunicationEvent> for TestActor {
    type Msg = TestActorMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: CommunicationEvent, _sender: Sender) {
        println!("{}: -> got msg: {:?}", ctx.myself.name(), msg);
        if let CommunicationEvent::RequestResponse {
            peer_id,
            request_id,
            event: ReqResEvent::Req(Request::Ping),
        } = msg
        {
            let response = CommunicationEvent::RequestResponse {
                peer_id,
                request_id,
                event: ReqResEvent::Res(Response::Pong),
            };
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
    let chan: ChannelRef<CommunicationEvent> = channel("remote-peer", &sys).unwrap();
    sys.actor_of_args::<CommunicationActor, _>("communication-actor", (local_keys, chan.clone()))
        .unwrap();
    sys.actor_of_args::<TestActor, _>("test-actor", chan).unwrap();
    std::thread::sleep(Duration::from_secs(600));
}

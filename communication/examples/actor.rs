// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example create a very basic test actor in the same actor system as the communication actor, and
//! a channel that the actors then use for communication. The CommunicationActor forwards incoming
//! requests to this `TestActor` that the response to a Ping with a Pong.
//! This can be tested by running this example and then pinging this peer with e.g. the local-echo
//! example.
//!
//! ```sh
//! $ cargo run --example actor
//! test-actor: -> got msg: SwarmInfo { peer_id: PeerId("12D3KooWAeCJuADLYj11jiTgyTvF3qK8VCxC6D79dru8prFiyAcE"), listeners: ["/ip4/127.0.0.1/tcp/42685"] }
//! ```
//!
//! ```sh
//! $ cargo run --example local-echo
//! # Ping the communication actor
//! PING "12D3KooWAeCJuADLYj11jiTgyTvF3qK8VCxC6D79dru8prFiyAcE"
//! ```

use core::time::Duration;
use libp2p::core::identity::Keypair;
use riker::actors::*;
use serde::{Deserialize, Serialize};
use stronghold_communication::{
    actor::{CommsActorConfig, CommunicationActor, CommunicationEvent},
    behaviour::message::P2PReqResEvent,
};

// The type of request that is send to/ from remote peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

// The type of response that is send to/ from a remote peer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
}

// An independent actor that communicates with the `CommunicationActor` via the channel.
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
        // subscribe to the topic where the CommunicationActor publishes its messages.
        let topic = Topic::from("from_swarm");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        self.chan.tell(
            Publish {
                msg: CommunicationEvent::GetSwarmInfo,
                topic: Topic::from("to_swarm"),
            },
            Some(BasicActorRef::from(ctx.myself())),
        );
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
                    topic: Topic::from("to_swarm"),
                },
                Some(BasicActorRef::from(ctx.myself())),
            );
        }
    }
}

fn main() {
    // Create the two actor within the same actor system
    let sys = ActorSystem::new().unwrap();
    // The key pair for transport level and noise encryption
    let local_keys = Keypair::generate_ed25519();
    // configure the CommunicationActor to use the channel.
    let chan: ChannelRef<CommunicationEvent<Request, Response>> = channel("p2p", &sys).unwrap();
    let config = CommsActorConfig::new(local_keys, None, Some(chan.clone()), None);
    sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", config)
        .unwrap();
    sys.actor_of_args::<TestActor, _>("test-actor", chan).unwrap();
    // Run for 5 minutes
    std::thread::sleep(Duration::from_secs(300));
}

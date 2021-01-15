// Copyright 2020-2021 IOTA Stiftung
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
use stronghold_communication::actor::{CommsActorConfig, CommunicationActor, CommunicationEvent};

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
#[derive(Default)]
struct TestActor;

impl Actor for TestActor {
    type Msg = CommunicationEvent<Request, Response>;

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let communication_actor = ctx.select("*").unwrap();
        communication_actor.try_tell(CommunicationEvent::<Request, Response>::GetSwarmInfo, ctx.myself());
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        println!("{}: -> got msg: {:?}", ctx.myself.name(), msg);
        if let CommunicationEvent::Request {
            peer_id: _,
            request_id: Some(request_id),
            request: Request::Ping,
        } = msg
        {
            let response = CommunicationEvent::<Request, Response>::Response {
                request_id,
                result: Ok(Response::Pong),
            };
            sender.unwrap().try_tell(response, ctx.myself()).unwrap();
        }
    }
}

fn main() {
    // Create the two actor within the same actor system
    let sys = ActorSystem::new().unwrap();
    // The key pair for encryption
    let local_keys = Keypair::generate_ed25519();
    let actor_ref = sys.actor_of::<TestActor>("test-actor").unwrap();
    let config = CommsActorConfig::new(local_keys, None, BasicActorRef::from(actor_ref));
    sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", config)
        .unwrap();
    // Run for 5 minutes
    std::thread::sleep(Duration::from_secs(300));
}

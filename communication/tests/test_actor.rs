// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use async_std::task;
use riker::actors::*;
use stronghold_communication::{
    actor::{
        ask, CommunicationActor, CommunicationConfig, CommunicationRequest, CommunicationResults, FirewallRequest,
        FirewallResponse,
    },
    libp2p::{Keypair, Multiaddr, PeerId},
};

use core::time::Duration;
use serde::{Deserialize, Serialize};

// the type of the send request and reponse messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Response {
    Pong,
}

// Dummy firewall that approves all requests
#[derive(Debug, Clone)]
struct Firewall;

impl ActorFactory for Firewall {
    fn create() -> Self {
        Firewall
    }
}

impl Actor for Firewall {
    type Msg = FirewallRequest<Request>;

    fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
        sender.unwrap().try_tell(FirewallResponse::Accept, None).unwrap()
    }
}

// blank client actor without any logic
#[derive(Clone, Debug)]
struct BlankActor;

impl ActorFactory for BlankActor {
    fn create() -> Self {
        BlankActor
    }
}

impl Actor for BlankActor {
    type Msg = Request;

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        ctx.stop(&ctx.myself);
    }

    fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, _sender: Sender) {}
}

fn init_system(
    sys: &ActorSystem,
    client: ActorRef<Request>,
) -> (PeerId, ActorRef<CommunicationRequest<Request, Request>>) {
    // init remote actor system
    let keys = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys.public());
    let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
    let config = CommunicationConfig::new(client, firewall);
    let comms_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys, config))
        .unwrap();
    (peer_id, comms_actor)
}

#[test]
fn msg_external_actor() {
    // local actor that receives the results for outgoing requests
    #[derive(Debug, Clone)]
    struct LocalActor;

    impl ActorFactory for LocalActor {
        fn create() -> Self {
            LocalActor
        }
    }

    impl Actor for LocalActor {
        type Msg = CommunicationResults<Response>;

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Stop
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationResults::RequestMsgResult(Ok(_)) = msg {
                ctx.stop(&ctx.myself);
            } else if let CommunicationResults::ConnectPeerResult(result) = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let req = CommunicationRequest::<Request, Request>::RequestMsg {
                    peer_id,
                    request: Request::Ping,
                };
                let communication_actor = ctx.select("/user/communication").unwrap();
                communication_actor.try_tell(req, ctx.myself());
            }
        }
    }

    // remote actor that responds to a requests from the local system
    #[derive(Debug, Clone)]
    struct RemoteActor {
        listening_addr: Multiaddr,
    }

    impl ActorFactoryArgs<Multiaddr> for RemoteActor {
        fn create_args(listening_addr: Multiaddr) -> Self {
            RemoteActor { listening_addr }
        }
    }

    impl Actor for RemoteActor {
        type Msg = Request;

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            let req = CommunicationRequest::<Request, Request>::StartListening(Some(self.listening_addr.clone()));
            let communication_actor = ctx.select("communication").unwrap();
            communication_actor.try_tell(req, ctx.myself());
        }

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            let response = Response::Pong;
            sender.unwrap().try_tell(response, None).unwrap();
        }
    }

    let remote_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8090".parse().unwrap();

    // init remote actor system
    let remote_sys = ActorSystem::new().unwrap();
    let client = remote_sys
        .actor_of_args::<RemoteActor, _>("remote-actor", remote_addr.clone())
        .unwrap();
    let (remote_peer_id, remote_comms) = init_system(&remote_sys, client);
    // remote comms start listening on the port
    let req = CommunicationRequest::<Request, Request>::StartListening(Some(remote_addr.clone()));
    remote_comms.tell(req, None);

    // local actor system
    let local_sys = ActorSystem::new().unwrap();
    let client = local_sys.actor_of::<BlankActor>("blank").unwrap();
    let (_, local_comms) = init_system(&local_sys, client);

    let local_actor = local_sys.actor_of::<LocalActor>("local-actor").unwrap();

    std::thread::sleep(Duration::new(1, 0));

    // send request, use local_actor as target for the response
    let req = CommunicationRequest::<Request, Request>::ConnectPeer {
        addr: remote_addr,
        peer_id: remote_peer_id,
    };
    local_comms.tell(req, local_actor.clone().into());

    while local_sys
        .user_root()
        .children()
        .any(|actor| actor == local_actor.clone().into())
    {
        // in order to lower cpu usage, sleep here
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn ask_swarm_info() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank").unwrap();
    let keys = Keypair::generate_ed25519();
    let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
    let config = CommunicationConfig::new(client, firewall);
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys.clone(), config))
        .unwrap();

    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
    match task::block_on(ask(
        &sys,
        &communication_actor,
        CommunicationRequest::StartListening(Some(addr.clone())),
    )) {
        CommunicationResults::<Response>::StartListeningResult(actual_addr) => {
            assert_eq!(addr, actual_addr.unwrap())
        }
        _ => panic!(),
    }

    let result = task::block_on(ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo));
    match result {
        CommunicationResults::<Response>::SwarmInfo { peer_id, listeners } => {
            assert_eq!(PeerId::from(keys.public()), peer_id);
            assert!(listeners.contains(&addr));
        }
        _ => panic!(),
    }
}

#[test]
fn ask_request() {
    #[derive(Clone)]
    struct TargetActor;

    impl ActorFactory for TargetActor {
        fn create() -> Self {
            TargetActor
        }
    }

    impl Actor for TargetActor {
        type Msg = Request;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            // echo msg back
            sender.unwrap().try_tell(Response::Pong, None).unwrap();
        }
    }

    // start remote actor system
    let remote_sys = ActorSystem::new().unwrap();
    let target_actor = remote_sys.actor_of::<TargetActor>("target").unwrap();
    let (_, remote_comms) = init_system(&remote_sys, target_actor);
    match task::block_on(ask(
        &remote_sys,
        &remote_comms,
        CommunicationRequest::StartListening(None),
    )) {
        CommunicationResults::<Response>::StartListeningResult(a) => {
            a.unwrap();
        }
        _ => panic!(),
    }

    // start local actor system
    let local_sys = ActorSystem::new().unwrap();
    let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
    let (_, local_comms) = init_system(&local_sys, blank_actor);

    std::thread::sleep(Duration::new(1, 0));
    // obtain information about the remote peer id and listeners
    let (remote_peer_id, listeners) =
        match task::block_on(ask(&remote_sys, &remote_comms, CommunicationRequest::GetSwarmInfo)) {
            CommunicationResults::<Response>::SwarmInfo { peer_id, listeners } => (peer_id, listeners),
            _ => panic!(),
        };
    // connect remote peer
    match task::block_on(ask(
        &local_sys,
        &local_comms,
        CommunicationRequest::ConnectPeer {
            addr: listeners.last().unwrap().clone(),
            peer_id: remote_peer_id,
        },
    )) {
        CommunicationResults::<Response>::ConnectPeerResult(Ok(peer_id)) => assert_eq!(peer_id, remote_peer_id),
        _ => panic!(),
    };

    // send message to remote peer
    match task::block_on(ask(
        &local_sys,
        &local_comms,
        CommunicationRequest::RequestMsg {
            peer_id: remote_peer_id,
            request: Request::Ping,
        },
    )) {
        CommunicationResults::<Response>::RequestMsgResult(Ok(res)) => assert_eq!(res, Response::Pong),
        _ => panic!(),
    };
    local_sys.stop(&local_comms);
    remote_sys.stop(&remote_comms);
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use riker::actors::*;
use stronghold_communication::{
    actor::{
        ask,
        firewall::{FirewallResponse, FirewallRule, OpenFirewall, RestrictConnectionFirewall},
        CommunicationActor, CommunicationConfig, CommunicationRequest, CommunicationResults, FirewallBlocked,
        KeepAlive, RequestMessageError,
    },
    behaviour::{BehaviourConfig, P2POutboundFailure},
    libp2p::{Keypair, Multiaddr, PeerId},
};

use core::task::{Context as TaskContext, Poll};
use futures::{future, prelude::*};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

fn init_system(
    sys: &ActorSystem,
    client: ActorRef<Request>,
) -> (PeerId, ActorRef<CommunicationRequest<Request, Request>>) {
    // init actor system
    let keys = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys.public());
    let firewall = sys.actor_of::<OpenFirewall<Request>>("firewall").unwrap();
    let actor_config = CommunicationConfig::new(client, firewall);
    let behaviour_config = BehaviourConfig::default();
    let communication_actor_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys, actor_config, behaviour_config),
        )
        .unwrap();
    (peer_id, communication_actor_actor)
}

// the type of the send request and reponse messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Response {
    Pong,
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
#[derive(Clone)]
struct ReplyActor;

impl ActorFactory for ReplyActor {
    fn create() -> Self {
        ReplyActor
    }
}

impl Actor for ReplyActor {
    type Msg = Request;

    fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
        // echo msg back
        sender.unwrap().try_tell(Response::Pong, None).unwrap();
    }
}

#[test]
fn msg_external_actor() {
    // local actor that receives the results for outgoing requests
    #[derive(Debug, Clone)]
    struct ActorA;

    impl ActorFactory for ActorA {
        fn create() -> Self {
            ActorA
        }
    }

    impl Actor for ActorA {
        type Msg = CommunicationResults<Response>;

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Stop
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationResults::RequestMsgResult(Ok(_)) = msg {
                ctx.stop(&ctx.myself);
            } else if let CommunicationResults::EstablishConnectionResult(result) = msg {
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

    // actor A system
    let sys_a = ActorSystem::new().unwrap();
    let client = sys_a.actor_of::<BlankActor>("blank").unwrap();
    let (_, communication_actor_a) = init_system(&sys_a, client);
    let actor_a = sys_a.actor_of::<ActorA>("actor-a").unwrap();

    // remote actor that responds to a requests from actor A system
    #[derive(Debug, Clone)]
    struct ActorB {
        listening_addr: Multiaddr,
    }

    impl ActorFactoryArgs<Multiaddr> for ActorB {
        fn create_args(listening_addr: Multiaddr) -> Self {
            ActorB { listening_addr }
        }
    }

    impl Actor for ActorB {
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

    // init actor B system
    let sys_b = ActorSystem::new().unwrap();
    let addr_b: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().expect("Invalid Multiaddress.");
    let client = sys_b.actor_of_args::<ActorB, _>("actor-b", addr_b.clone()).unwrap();
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, client);

    // communication B start listening on the port
    let req = CommunicationRequest::<Request, Request>::StartListening(Some(addr_b.clone()));
    communication_actor_b.tell(req, None);

    std::thread::sleep(Duration::new(1, 0));

    // send request, use actor A  as target for the response
    let req = CommunicationRequest::<Request, Request>::EstablishConnection {
        addr: addr_b,
        peer_id: peer_b_id,
        keep_alive: KeepAlive::Unlimited,
    };
    communication_actor_a.tell(req, actor_a.clone().into());

    while sys_a
        .user_root()
        .children()
        .any(|actor| actor == actor_a.clone().into())
    {
        // in order to lower cpu usage, sleep here
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

// ==== test ask pattern & halting

async fn try_ask(
    ctx: &ActorSystem,
    receiver: &ActorRef<CommunicationRequest<Request, Request>>,
    msg: CommunicationRequest<Request, Request>,
) -> Option<CommunicationResults<Response>> {
    let start = Instant::now();
    let mut asked = ask(ctx, receiver, msg);
    task::block_on(future::poll_fn(|cx: &mut TaskContext<'_>| match asked.poll_unpin(cx) {
        Poll::Ready(r) => Poll::Ready(Some(r)),
        Poll::Pending => {
            if start.elapsed() > Duration::new(3, 0) {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }))
}

#[test]
fn ask_swarm_info() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank").unwrap();
    let keys = Keypair::generate_ed25519();
    let firewall = sys.actor_of::<OpenFirewall<Request>>("firewall").unwrap();
    let actor_config = CommunicationConfig::new(client, firewall);
    let behaviour_config = BehaviourConfig::default();
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys.clone(), actor_config, behaviour_config),
        )
        .unwrap();

    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8096".parse().expect("Invalid Multiaddress.");
    match task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::StartListening(Some(addr.clone())),
    )) {
        Some(CommunicationResults::StartListeningResult(actual_addr)) => {
            assert_eq!(addr, actual_addr.unwrap())
        }
        other => panic!(other),
    }

    let result = task::block_on(try_ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo));
    match result {
        Some(CommunicationResults::SwarmInfo {
            peer_id,
            listeners,
            connections,
        }) => {
            assert_eq!(PeerId::from(keys.public()), peer_id);
            assert!(listeners.contains(&addr));
            assert_eq!(connections.len(), 0)
        }
        other => panic!(other),
    }
}

#[test]
fn ask_request() {
    // start actor B system
    let sys_b = ActorSystem::new().unwrap();
    let target_actor = sys_b.actor_of::<ReplyActor>("target").unwrap();
    let (_, communication_actor_b) = init_system(&sys_b, target_actor);
    match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::StartListening(None),
    )) {
        Some(CommunicationResults::StartListeningResult(a)) => {
            a.unwrap();
        }
        other => panic!(other),
    }

    // start actor A system
    let sys_a = ActorSystem::new().unwrap();
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").unwrap();
    let (_, communication_actor_a) = init_system(&sys_a, blank_actor);

    // obtain information about peer Bs id and listeners
    let (peer_b_id, listeners) = match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::GetSwarmInfo,
    )) {
        Some(CommunicationResults::SwarmInfo {
            peer_id,
            listeners,
            connections: _,
        }) => (peer_id, listeners),
        other => panic!(other),
    };

    // connect peer A with peer B
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::EstablishConnection {
            addr: listeners.last().unwrap().clone(),
            peer_id: peer_b_id,
            keep_alive: KeepAlive::Unlimited,
        },
    )) {
        Some(CommunicationResults::EstablishConnectionResult(Ok(peer_id))) => assert_eq!(peer_id, peer_b_id),
        other => panic!(other),
    };

    // send message to from A to B
    if let Some(CommunicationResults::RequestMsgResult(res)) = task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        assert!(res.is_ok());
    } else {
        panic!()
    }
    sys_a.stop(&communication_actor_a);
    sys_b.stop(&communication_actor_b);
}

#[test]
fn no_soliloquize() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank").unwrap();
    let (own_peer_id, communication_actor) = init_system(&sys, client);
    if let Some(CommunicationResults::StartListeningResult(res)) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::StartListening(None),
    )) {
        assert!(res.is_ok())
    } else {
        panic!();
    }
    let listeners = match task::block_on(try_ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo)) {
        Some(CommunicationResults::SwarmInfo {
            peer_id: _,
            listeners,
            connections: _,
        }) => listeners,
        other => panic!(other),
    };

    for addr in listeners {
        // try connect self
        if let Some(CommunicationResults::EstablishConnectionResult(res)) = task::block_on(try_ask(
            &sys,
            &communication_actor,
            CommunicationRequest::EstablishConnection {
                addr,
                peer_id: own_peer_id,
                keep_alive: KeepAlive::Unlimited,
            },
        )) {
            assert!(res.is_err())
        } else {
            panic!();
        }
    }
    // try send request to self
    if let Some(CommunicationResults::RequestMsgResult(res)) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::RequestMsg {
            peer_id: own_peer_id,
            request: Request::Ping,
        },
    )) {
        assert!(res.is_err())
    } else {
        panic!()
    }
}

#[test]
#[should_panic(expected = "Could not establish connection")]
fn connect_invalid() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank").unwrap();
    let (_, communication_actor) = init_system(&sys, client);
    if let Some(CommunicationResults::EstablishConnectionResult(Err(_))) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::EstablishConnection {
            addr: "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."),
            peer_id: PeerId::random(),
            keep_alive: KeepAlive::Unlimited,
        },
    )) {
        panic!("Could not establish connection");
    }
}

#[test]
fn manage_connection() {
    // init actor A
    let sys_a = ActorSystem::new().unwrap();
    let client = sys_a.actor_of::<BlankActor>("blank").unwrap();
    let (peer_a_id, communication_actor_a) = init_system(&sys_a, client);

    // init actor B
    let sys_b = ActorSystem::new().unwrap();
    let client = sys_b.actor_of::<ReplyActor>("target").unwrap();
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, client);

    // try to send a request between the peers without connecting them first
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(res)) => assert!(res.is_err()),
        other => panic!(other),
    }

    // peer B starts listening
    let addr_b = match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::StartListening(None),
    )) {
        Some(CommunicationResults::StartListeningResult(addr)) => addr.unwrap(),
        other => panic!(other),
    };

    // establish connection
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::EstablishConnection {
            addr: addr_b,
            peer_id: peer_b_id,
            keep_alive: KeepAlive::Unlimited,
        },
    )) {
        Some(CommunicationResults::EstablishConnectionResult(res)) => assert!(res.is_ok()),
        other => panic!(other),
    }

    // check if peer A is listed in peer Bs connections
    match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::GetSwarmInfo,
    )) {
        Some(CommunicationResults::SwarmInfo {
            peer_id: _,
            listeners: _,
            connections,
        }) => {
            assert!(connections.into_iter().any(|(peer, _)| peer == peer_a_id))
        }
        other => panic!(other),
    };

    // check if peer B is listed in peer As connections
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::GetSwarmInfo,
    )) {
        Some(CommunicationResults::SwarmInfo {
            peer_id: _,
            listeners: _,
            connections,
        }) => {
            assert!(connections.into_iter().any(|(peer, _)| peer == peer_b_id))
        }
        other => panic!(other),
    };

    // send request after peers established a connection
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(res)) => assert!(res.is_ok()),
        other => panic!(other),
    }

    // Peer B closes connection
    match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::CloseConnection(peer_a_id),
    )) {
        Some(CommunicationResults::ClosedConnection) => {}
        other => panic!(other),
    };

    // send request after peer B closed connection
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(res)) => assert!(res.is_err()),
        other => panic!(other),
    }
}

#[test]
fn firewall_rules() {
    // Actor A
    let sys_a = ActorSystem::new().unwrap();
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").unwrap();
    let keys = Keypair::generate_ed25519();
    let peer_a_id = PeerId::from(keys.public());
    let behaviour_config = BehaviourConfig::default();
    // Set firewall to block all connections per default.
    let firewall_a = sys_a
        .actor_of_args::<RestrictConnectionFirewall<Request>, _>("firewall", FirewallResponse::Reject)
        .unwrap();
    let actor_config = CommunicationConfig::new(blank_actor, firewall_a.clone());
    let communication_actor_a = sys_a
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys, actor_config, behaviour_config.clone()),
        )
        .unwrap();

    // Actor B with firewall that rejects all connections.
    let sys_b = ActorSystem::new().unwrap();
    let target_actor = sys_b.actor_of::<ReplyActor>("target").unwrap();
    let keys = Keypair::generate_ed25519();
    let peer_b_id = PeerId::from(keys.public());
    // Set firewall to block all connections per default.
    let firewall_b = sys_b
        .actor_of_args::<RestrictConnectionFirewall<Request>, _>("firewall", FirewallResponse::Reject)
        .unwrap();
    let actor_config = CommunicationConfig::new(target_actor, firewall_b.clone());
    let communication_actor_b = sys_b
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys, actor_config, behaviour_config),
        )
        .unwrap();

    let addr_b = match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::StartListening(None),
    )) {
        Some(CommunicationResults::StartListeningResult(a)) => a.unwrap(),
        other => panic!(other),
    };

    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::EstablishConnection {
            addr: addr_b,
            peer_id: peer_b_id,
            keep_alive: KeepAlive::Unlimited,
        },
    )) {
        Some(CommunicationResults::EstablishConnectionResult(res)) => assert!(res.is_ok()),
        other => panic!(other),
    }

    // Outgoing request should be blocked by As firewall
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(Err(RequestMessageError::Rejected(FirewallBlocked::Local)))) => {}
        other => panic!(other),
    }

    // Set rule for As firewall to allow requests to B
    let rule = FirewallRule::new(peer_b_id, FirewallResponse::Accept);
    firewall_a.tell(rule, None);

    // Incoming request should be blocked by Bs firewall
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(Err(RequestMessageError::Rejected(FirewallBlocked::Remote))))
        | Some(CommunicationResults::RequestMsgResult(Err(RequestMessageError::Outbound(
            P2POutboundFailure::Timeout,
        )))) => {}
        other => panic!(other),
    }

    // Set rule for Bs firewall to allow requests from A.
    let rule = FirewallRule::new(peer_a_id, FirewallResponse::Accept);
    firewall_b.tell(rule, None);

    // Send request
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(res)) => assert!(res.is_ok()),
        other => panic!(other),
    }

    // Forbid requests from A again
    let rule = FirewallRule::new(peer_a_id, FirewallResponse::Reject);
    firewall_b.tell(rule, None);

    // Requests should be blocked from B again
    match task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Ping,
        },
    )) {
        Some(CommunicationResults::RequestMsgResult(Err(RequestMessageError::Rejected(FirewallBlocked::Remote))))
        | Some(CommunicationResults::RequestMsgResult(Err(RequestMessageError::Outbound(
            P2POutboundFailure::Timeout,
        )))) => {}
        other => panic!(other),
    }
}

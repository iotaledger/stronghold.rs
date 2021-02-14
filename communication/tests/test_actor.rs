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

use core::task::{Context as TaskContext, Poll};
use futures::{future, prelude::*};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

fn init_system(
    sys: &ActorSystem,
    client: ActorRef<Request>,
) -> Option<(PeerId, ActorRef<CommunicationRequest<Request, Request>>)> {
    // init remote actor system
    let keys = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys.public());
    let firewall = sys.actor_of::<Firewall>("firewall");
    if firewall.is_err() {
        return None;
    }
    let config = CommunicationConfig::new(client, firewall.unwrap());
    let comms_actor = sys.actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys, config));
    comms_actor.ok().map(|comms_actor| (peer_id, comms_actor))
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
    let (remote_peer_id, remote_comms) = init_system(&remote_sys, client).unwrap();
    // remote comms start listening on the port
    let req = CommunicationRequest::<Request, Request>::StartListening(Some(remote_addr.clone()));
    remote_comms.tell(req, None);

    // local actor system
    let local_sys = ActorSystem::new().unwrap();
    let client = local_sys.actor_of::<BlankActor>("blank").unwrap();
    let (_, local_comms) = init_system(&local_sys, client).unwrap();

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
    let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
    let config = CommunicationConfig::new(client, firewall);
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys.clone(), config))
        .unwrap();

    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
    match task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::StartListening(Some(addr.clone())),
    )) {
        Some(CommunicationResults::StartListeningResult(actual_addr)) => {
            assert_eq!(addr, actual_addr.unwrap())
        }
        _ => panic!(),
    }

    let result = task::block_on(try_ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo));
    match result {
        Some(CommunicationResults::SwarmInfo { peer_id, listeners }) => {
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
    let (_, remote_comms) = init_system(&remote_sys, target_actor).unwrap();
    match task::block_on(try_ask(
        &remote_sys,
        &remote_comms,
        CommunicationRequest::StartListening(None),
    )) {
        Some(CommunicationResults::StartListeningResult(a)) => {
            a.unwrap();
        }
        _ => panic!(),
    }

    // start local actor system
    let local_sys = ActorSystem::new().unwrap();
    let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
    let (_, local_comms) = init_system(&local_sys, blank_actor).unwrap();

    // obtain information about the remote peer id and listeners
    let (remote_peer_id, listeners) =
        match task::block_on(try_ask(&remote_sys, &remote_comms, CommunicationRequest::GetSwarmInfo)) {
            Some(CommunicationResults::SwarmInfo { peer_id, listeners }) => (peer_id, listeners),
            _ => panic!(),
        };

    // connect remote peer
    match task::block_on(try_ask(
        &local_sys,
        &local_comms,
        CommunicationRequest::ConnectPeer {
            addr: listeners.last().unwrap().clone(),
            peer_id: remote_peer_id,
        },
    )) {
        Some(CommunicationResults::ConnectPeerResult(Ok(peer_id))) => assert_eq!(peer_id, remote_peer_id),
        _ => panic!(),
    };

    // send message to remote peer
    if let Some(CommunicationResults::RequestMsgResult(Ok(res))) = task::block_on(try_ask(
        &local_sys,
        &local_comms,
        CommunicationRequest::RequestMsg {
            peer_id: remote_peer_id,
            request: Request::Ping,
        },
    )) {
        assert_eq!(res, Response::Pong);
    } else {
        panic!()
    }
    local_sys.stop(&local_comms);
    remote_sys.stop(&remote_comms);
}

#[test]
fn no_soliloquize() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank").unwrap();
    let (own_peer_id, communication_actor) = init_system(&sys, client).unwrap();
    if let Some(CommunicationResults::StartListeningResult(Ok(_))) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::StartListening(None),
    )) {
    } else {
        panic!();
    }
    let listeners = match task::block_on(try_ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo)) {
        Some(CommunicationResults::SwarmInfo { peer_id: _, listeners }) => listeners,
        _ => panic!(),
    };

    for addr in listeners {
        // try connect self
        if let Some(CommunicationResults::ConnectPeerResult(Err(_))) = task::block_on(try_ask(
            &sys,
            &communication_actor,
            CommunicationRequest::ConnectPeer {
                addr,
                peer_id: own_peer_id,
            },
        )) {
        } else {
            panic!();
        }
    }
    // try send request to self
    if let Some(CommunicationResults::RequestMsgResult(Err(_))) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::RequestMsg {
            peer_id: own_peer_id,
            request: Request::Ping,
        },
    )) {
    } else {
        panic!()
    }
}

#[test]
#[should_panic]
fn connect_invalid() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank");
    if client.is_err() {
        return;
    }
    let opt = init_system(&sys, client.unwrap());
    if opt.is_none() {
        return;
    }
    let (_, communication_actor) = opt.unwrap();
    if let Some(CommunicationResults::ConnectPeerResult(Err(_))) = task::block_on(try_ask(
        &sys,
        &communication_actor,
        CommunicationRequest::ConnectPeer {
            addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            peer_id: PeerId::random(),
        },
    )) {
        panic!();
    }
}

#[test]
#[cfg(not(feature = "mdns"))]
#[should_panic]
fn send_request_unconnected() {
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank");
    if client.is_err() {
        return;
    }

    // init actor a
    let opt = init_system(&sys, client.unwrap());
    if opt.is_none() {
        return;
    }
    let (peer_a_id, communication_actor_a) = opt.unwrap();
    if let Some(CommunicationResults::StartListeningResult(Ok(_))) = task::block_on(try_ask(
        &sys,
        &communication_actor_a,
        CommunicationRequest::StartListening(None),
    )) {
    } else {
        return;
    };

    // init actor b
    let sys = ActorSystem::new().unwrap();
    let client = sys.actor_of::<BlankActor>("blank");
    if client.is_err() {
        return;
    }
    let opt = init_system(&sys, client.unwrap());
    if opt.is_none() {
        return;
    }
    let (_, communication_actor_b) = opt.unwrap();

    // try to send a request between the peers without connecting them first
    let res = task::block_on(try_ask(
        &sys,
        &communication_actor_b,
        CommunicationRequest::RequestMsg {
            peer_id: peer_a_id,
            request: Request::Ping,
        },
    ));
    if let Some(CommunicationResults::RequestMsgResult(Err(_))) = res {
        panic!()
    }
}

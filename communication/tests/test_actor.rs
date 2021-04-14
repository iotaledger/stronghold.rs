// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication::{
    actor::{
        CommunicationActor, CommunicationActorConfig, CommunicationRequest, CommunicationResults, ConnectPeerError,
        EstablishedConnection, FirewallPermission, FirewallRule, PermissionValue, RelayDirection, RequestDirection,
        RequestMessageError, RequestPermissions, ToPermissionVariants, VariantPermission,
    },
    behaviour::{BehaviourConfig, P2POutboundFailure},
    libp2p::{Keypair, Multiaddr, PeerId},
};
use riker::actors::*;
use stronghold_utils::ask;

use core::task::{Context as TaskContext, Poll};
use futures::{future, prelude::*};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

fn init_system(
    sys: &ActorSystem,
    client: ActorRef<Request>,
    default: FirewallPermission,
) -> (PeerId, ActorRef<CommunicationRequest<Request, Request>>) {
    // init actor system
    let keys = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys.public());
    let behaviour_config = BehaviourConfig::default();
    let actor_config = CommunicationActorConfig {
        client,
        firewall_default_in: default,
        firewall_default_out: default,
    };
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys, actor_config, behaviour_config),
        )
        .expect("Failed to init actor.");
    (peer_id, communication_actor)
}

// the type of the send request and reponse messages
#[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
pub enum Request {
    Ping,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, RequestPermissions)]
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
        sender
            .expect("Missing sender.")
            .try_tell(Response::Pong, None)
            .expect("Could not tell response.");
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
            } else if let CommunicationResults::AddPeerResult(result) = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let req = CommunicationRequest::<Request, Request>::RequestMsg {
                    peer_id,
                    request: Request::Ping,
                };
                let communication_actor = ctx
                    .select("/user/communication")
                    .expect("Failed to select communication actor.");
                communication_actor.try_tell(req, ctx.myself());
            }
        }
    }

    // actor A system
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (_, communication_actor_a) = init_system(&sys_a, client, FirewallPermission::all());
    let actor_a = sys_a.actor_of::<ActorA>("actor-a").expect("Failed to init actor.");

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

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            sender
                .expect("Missing sender.")
                .try_tell(Response::Pong, None)
                .expect("Could not tell response.");
        }
    }

    // init actor B system
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let addr_b: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().expect("Invalid Multiaddress.");
    let client = sys_b
        .actor_of_args::<ActorB, _>("actor-b", addr_b.clone())
        .expect("Failed to init actor.");
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, client, FirewallPermission::all());

    // communication B start listening on the port
    let req = CommunicationRequest::<Request, Request>::StartListening(Some(addr_b.clone()));
    communication_actor_b.tell(req, None);

    std::thread::sleep(Duration::new(1, 0));

    // send request, use actor A  as target for the response
    let req = CommunicationRequest::<Request, Request>::AddPeer {
        addr: Some(addr_b),
        peer_id: peer_b_id,
        is_relay: None,
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

fn add_peer(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
    peer_id: PeerId,
    addr: Option<Multiaddr>,
    is_relay: Option<RelayDirection>,
) -> Result<PeerId, ConnectPeerError> {
    match task::block_on(try_ask(
        sys,
        communication_actor,
        CommunicationRequest::AddPeer {
            addr,
            peer_id,
            is_relay,
        },
    )) {
        Some(CommunicationResults::AddPeerResult(res)) => res,
        other => panic!("{:?}", other),
    }
}

fn start_listening(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
    addr: Option<Multiaddr>,
) -> Multiaddr {
    match task::block_on(try_ask(
        sys,
        communication_actor,
        CommunicationRequest::StartListening(addr),
    )) {
        Some(CommunicationResults::StartListeningResult(a)) => a.expect("Failed to start listening."),
        _ => panic!("Unexpected Response"),
    }
}

fn send_request(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
    peer_id: PeerId,
) -> Result<Response, RequestMessageError> {
    if let Some(CommunicationResults::RequestMsgResult(res)) = task::block_on(try_ask(
        sys,
        communication_actor,
        CommunicationRequest::RequestMsg {
            peer_id,
            request: Request::Ping,
        },
    )) {
        res
    } else {
        panic!("Unexpected Response");
    }
}

fn set_firewall_rule(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
    peer_id: PeerId,
    direction: RequestDirection,
    permission: FirewallPermission,
) {
    match task::block_on(try_ask(
        sys,
        communication_actor,
        CommunicationRequest::ConfigureFirewall(FirewallRule::SetRules {
            peers: vec![peer_id],
            set_default: false,
            direction,
            permission,
        }),
    )) {
        Some(CommunicationResults::ConfigureFirewallAck) => {}
        _ => panic!("Unexpected Response"),
    }
}
fn config_relay(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
    peer_id: PeerId,
    direction: RelayDirection,
) -> PeerId {
    match task::block_on(try_ask(
        sys,
        communication_actor,
        CommunicationRequest::ConfigRelay { peer_id, direction },
    )) {
        Some(CommunicationResults::ConfigRelayResult(peer_id)) => peer_id.expect("Failed to config relay."),
        _ => panic!("Unexpected Response"),
    }
}

fn get_swarm_info(
    sys: &ActorSystem,
    communication_actor: &ActorRef<CommunicationRequest<Request, Request>>,
) -> (PeerId, Vec<Multiaddr>, Vec<(PeerId, EstablishedConnection)>) {
    match task::block_on(try_ask(sys, communication_actor, CommunicationRequest::GetSwarmInfo)) {
        Some(CommunicationResults::SwarmInfo {
            peer_id,
            listeners,
            connections,
        }) => (peer_id, listeners, connections),
        _ => panic!("Unexpected Response"),
    }
}

#[test]
fn ask_swarm_info() {
    let sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let keys = Keypair::generate_ed25519();
    let behaviour_config = BehaviourConfig::default();
    let actor_config = CommunicationActorConfig {
        client,
        firewall_default_in: FirewallPermission::all(),
        firewall_default_out: FirewallPermission::all(),
    };
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
            "communication",
            (keys.clone(), actor_config, behaviour_config),
        )
        .expect("Failed to init actor.");

    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8096".parse().expect("Invalid Multiaddress.");
    let actual_addr = start_listening(&sys, &communication_actor, Some(addr.clone()));
    assert_eq!(addr, actual_addr);

    let (peer_id, listeners, connections) = get_swarm_info(&sys, &communication_actor);
    assert_eq!(PeerId::from(keys.public()), peer_id);
    assert!(listeners.contains(&addr));
    assert_eq!(connections.len(), 0);
}

#[test]
fn ask_request() {
    // start actor B system
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let target_actor = sys_b.actor_of::<ReplyActor>("target").expect("Failed to init actor.");
    let (_, communication_actor_b) = init_system(&sys_b, target_actor, FirewallPermission::all());

    start_listening(&sys_b, &communication_actor_b, None);

    // start actor A system
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (_, communication_actor_a) = init_system(&sys_a, blank_actor, FirewallPermission::all());

    // obtain information about peer Bs id and listeners
    let (peer_b_id, listeners, _) = get_swarm_info(&sys_b, &communication_actor_b);

    // connect peer A with peer B
    let connected_peer = add_peer(
        &sys_a,
        &communication_actor_a,
        peer_b_id,
        listeners.last().cloned(),
        None,
    )
    .expect("Could not establish connection.");
    assert_eq!(connected_peer, peer_b_id);

    // send message to from A to B
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_ok());
    sys_a.stop(&communication_actor_a);
    sys_b.stop(&communication_actor_b);
}

#[test]
fn no_soliloquize() {
    let sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (own_peer_id, communication_actor) = init_system(&sys, client, FirewallPermission::all());
    start_listening(&sys, &communication_actor, None);

    let (_, listeners, _) = get_swarm_info(&sys, &communication_actor);
    for addr in listeners {
        // try connect self
        let res = add_peer(&sys, &communication_actor, own_peer_id, Some(addr), None);
        assert!(res.is_err())
    }
    // try send request to self
    let res = send_request(&sys, &communication_actor, own_peer_id);
    assert!(res.is_err());
}

#[test]
#[should_panic(expected = "Could not establish connection")]
fn connect_invalid() {
    let sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (_, communication_actor) = init_system(&sys, client, FirewallPermission::all());
    if add_peer(&sys, &communication_actor, PeerId::random(), None, None).is_err() {
        panic!("Could not establish connection");
    }
}

#[test]
fn manage_connection() {
    // init actor A
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (peer_a_id, communication_actor_a) = init_system(&sys_a, client, FirewallPermission::all());

    // init actor B
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let client = sys_b.actor_of::<ReplyActor>("target").expect("Failed to init actor.");
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, client, FirewallPermission::all());

    // try to send a request between the peers without connecting them first
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_err());

    // peer B starts listening
    let addr_b = start_listening(&sys_b, &communication_actor_b, None);

    // establish connection
    let res = add_peer(&sys_a, &communication_actor_a, peer_b_id, Some(addr_b), None);
    assert!(res.is_ok());

    // check if peer A is listed in peer Bs connections
    let (_, _, connections) = get_swarm_info(&sys_b, &communication_actor_b);
    assert!(connections.into_iter().any(|(peer, _)| peer == peer_a_id));

    // check if peer B is listed in peer As connections
    let (_, _, connections) = get_swarm_info(&sys_a, &communication_actor_a);
    assert!(connections.into_iter().any(|(peer, _)| peer == peer_b_id));

    // send request after peers established a connection
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_ok());

    // Peer B bans Peer A
    match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::BanPeer(peer_a_id),
    )) {
        Some(CommunicationResults::BannedPeerAck(peer_id)) => assert_eq!(peer_id, peer_a_id),
        _ => panic!("Unexpected Response"),
    };

    // send request after peer B closed connection
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_err());
}

#[test]
fn firewall_forbid_in() {
    // Actor A with firewall that allows all connections.
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (peer_a_id, communication_actor_a) = init_system(&sys_a, blank_actor, FirewallPermission::all());

    // Actor B with firewall that rejects all connections.
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let target_actor = sys_b.actor_of::<ReplyActor>("target").expect("Failed to init actor.");
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, target_actor, FirewallPermission::none());

    let addr_b = start_listening(&sys_b, &communication_actor_b, None);

    let res = add_peer(&sys_a, &communication_actor_a, peer_b_id, Some(addr_b), None);
    assert!(res.is_ok());

    // Incoming request should be blocked by Bs firewall
    match send_request(&sys_a, &communication_actor_a, peer_b_id) {
        Err(RequestMessageError::Outbound(P2POutboundFailure::Timeout)) => {}
        _ => panic!("Remote firewall should have blocked the request"),
    }

    // Set rule for Bs firewall to allow requests from A.
    set_firewall_rule(
        &sys_b,
        &communication_actor_b,
        peer_a_id,
        RequestDirection::In,
        FirewallPermission::all(),
    );

    // Send request
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_ok());

    // Forbid requests from A again
    set_firewall_rule(
        &sys_b,
        &communication_actor_b,
        peer_a_id,
        RequestDirection::In,
        FirewallPermission::none(),
    );

    // Requests should be blocked from B again
    match send_request(&sys_a, &communication_actor_a, peer_b_id) {
        Err(RequestMessageError::Outbound(P2POutboundFailure::Timeout)) => {}
        _ => panic!("Remote firewall should have blocked the request"),
    }
}

#[test]
fn firewall_forbid_out() {
    // Actor A that rejects all traffic
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (_, communication_actor_a) = init_system(&sys_a, blank_actor, FirewallPermission::none());

    // Actor B that allows all traffic
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let target_actor = sys_b.actor_of::<ReplyActor>("target").expect("Failed to init actor.");
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, target_actor, FirewallPermission::all());

    let addr_b = start_listening(&sys_b, &communication_actor_b, None);

    let res = add_peer(&sys_a, &communication_actor_a, peer_b_id, Some(addr_b), None);
    assert!(res.is_ok());

    // Outgoing request should be blocked by As firewall
    match send_request(&sys_a, &communication_actor_a, peer_b_id) {
        Err(RequestMessageError::LocalFirewallRejected) => {}
        _ => panic!("Local firewall should have blocked the request."),
    }

    // Set rule for As firewall to allow requests to B
    set_firewall_rule(
        &sys_a,
        &communication_actor_a,
        peer_b_id,
        RequestDirection::Out,
        FirewallPermission::all(),
    );

    // Send request
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_ok());

    // Forbid requests to B again
    set_firewall_rule(
        &sys_a,
        &communication_actor_a,
        peer_b_id,
        RequestDirection::Out,
        FirewallPermission::none(),
    );

    // Requests should be blocked from A again
    match send_request(&sys_a, &communication_actor_a, peer_b_id) {
        Err(RequestMessageError::LocalFirewallRejected) => {}
        _ => panic!("Remote firewall should have blocked the request"),
    }
}

#[test]
fn firewall_rules_selective() {
    // Actor A that allows all traffic
    let sys_a = ActorSystem::new().expect("Failed to create actor system.");
    let blank_actor = sys_a.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (peer_a_id, communication_actor_a) = init_system(&sys_a, blank_actor, FirewallPermission::all());

    // Actor B with firewall that rejects all connections.
    let sys_b = ActorSystem::new().expect("Failed to create actor system.");
    let target_actor = sys_b.actor_of::<ReplyActor>("target").expect("Failed to init actor.");
    let (peer_b_id, communication_actor_b) = init_system(&sys_b, target_actor, FirewallPermission::none());

    let addr_b = start_listening(&sys_b, &communication_actor_b, None);

    let res = add_peer(&sys_a, &communication_actor_a, peer_b_id, Some(addr_b), None);
    assert!(res.is_ok());

    // set B's firewall to only allow Request::Ping
    let permission = RequestPermission::Ping.permission();
    match task::block_on(try_ask(
        &sys_b,
        &communication_actor_b,
        CommunicationRequest::ConfigureFirewall(FirewallRule::AddPermissions {
            peers: vec![peer_a_id],
            change_default: false,
            direction: RequestDirection::In,
            permissions: vec![permission],
        }),
    )) {
        Some(CommunicationResults::ConfigureFirewallAck) => {}
        _ => panic!("Unexpected Response"),
    }

    // Request::Ping should be allowed
    let res = send_request(&sys_a, &communication_actor_a, peer_b_id);
    assert!(res.is_ok());

    // Request::Other should not be allowed
    if let Some(CommunicationResults::RequestMsgResult(res)) = task::block_on(try_ask(
        &sys_a,
        &communication_actor_a,
        CommunicationRequest::RequestMsg {
            peer_id: peer_b_id,
            request: Request::Other,
        },
    )) {
        match res {
            Err(RequestMessageError::Outbound(P2POutboundFailure::Timeout)) => {}
            _ => panic!("Remote firewall should have blocked the request"),
        }
    } else {
        panic!("Unexpected Response");
    }
}

#[test]
fn relay() {
    // init relay system and start listening
    let relay_sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = relay_sys
        .actor_of::<BlankActor>("blank")
        .expect("Failed to init actor.");
    let (relay_peer_id, relay_comms_actor) = init_system(&relay_sys, client, FirewallPermission::all());
    let relay_addr = start_listening(&relay_sys, &relay_comms_actor, None);

    // init source system and add relay for dialing
    let src_sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = src_sys.actor_of::<BlankActor>("blank").expect("Failed to init actor.");
    let (src_peer_id, src_comms_actor) = init_system(&src_sys, client, FirewallPermission::all());
    let peer_id = add_peer(
        &src_sys,
        &src_comms_actor,
        relay_peer_id,
        Some(relay_addr.clone()),
        Some(RelayDirection::Dialing),
    );
    assert_eq!(peer_id.expect("Peer could not be reached."), relay_peer_id);

    // init destination and add relay for listening and dialing
    let dest_sys = ActorSystem::new().expect("Failed to create actor system.");
    let client = dest_sys
        .actor_of::<ReplyActor>("destination")
        .expect("Failed to init actor.");
    let (dest_peer_id, dest_comms_actor) = init_system(&dest_sys, client, FirewallPermission::all());
    let peer_id = add_peer(
        &dest_sys,
        &dest_comms_actor,
        relay_peer_id,
        Some(relay_addr),
        Some(RelayDirection::Both),
    );
    assert_eq!(peer_id.expect("Peer could not be reached."), relay_peer_id);

    // source peer adds dst peer without address, so that relay is used
    let peer_id = add_peer(&src_sys, &src_comms_actor, dest_peer_id, None, None);
    assert_eq!(peer_id.expect("Peer could not be reached."), dest_peer_id);

    // destination peer should not be able to reach source peer since it only uses relay for dialing
    let peer_id = add_peer(&dest_sys, &dest_comms_actor, src_peer_id, None, None);
    assert!(peer_id.is_err());

    // Sending request from source to destination should be successful
    let res = send_request(&src_sys, &src_comms_actor, dest_peer_id);
    assert!(res.is_ok());

    // destination stops listening to relay and only uses it for Dialing
    let peer_id = config_relay(&dest_sys, &dest_comms_actor, relay_peer_id, RelayDirection::Dialing);
    assert_eq!(peer_id, relay_peer_id);

    // Sending request from source to destination should not be allowed anymore
    let res = send_request(&src_sys, &src_comms_actor, dest_peer_id);
    assert!(res.is_err());
}

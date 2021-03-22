// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication::{
    behaviour::{
        BehaviourConfig, MessageEvent, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent, RequestEnvelope,
    },
    libp2p::{Keypair, Multiaddr, PeerId, Protocol, Swarm, SwarmEvent},
};
use core::{ops::Deref, str::FromStr, time::Duration};
use futures::future;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Empty;

fn mock_swarm<Req: MessageEvent, Res: MessageEvent>() -> Swarm<P2PNetworkBehaviour<Req, Res>> {
    let local_keys = Keypair::generate_ed25519();
    let config = BehaviourConfig::default();
    task::block_on(P2PNetworkBehaviour::init_swarm(local_keys, config)).expect("Failed to init swarm.")
}

fn mock_addr() -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::new(127, 0, 0, 1)))
        .with(Protocol::Tcp(0))
}

fn start_listening<Req: MessageEvent, Res: MessageEvent>(
    swarm: &mut Swarm<P2PNetworkBehaviour<Req, Res>>,
) -> Option<Multiaddr> {
    task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return Some(addr),
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                }
                | SwarmEvent::ListenerError { error: _ } => return None,
                _ => {}
            }
        }
    })
}

fn establish_connection<Req: MessageEvent, Res: MessageEvent>(
    target_id: PeerId,
    target_addr: Multiaddr,
    swarm: &mut Swarm<P2PNetworkBehaviour<Req, Res>>,
) -> Option<()> {
    Swarm::dial_addr(swarm, target_addr).expect("Failed to dial address.");
    task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                } => {
                    assert_eq!(peer_id, target_id);
                    return Some(());
                }
                SwarmEvent::ConnectionClosed {
                    peer_id: _,
                    endpoint: _,
                    num_established: _,
                    cause: _,
                }
                | SwarmEvent::UnreachableAddr {
                    peer_id: _,
                    address: _,
                    error: _,
                    attempts_remaining: 0,
                }
                | SwarmEvent::UnknownPeerUnreachableAddr { address: _, error: _ } => return None,
                _ => {}
            }
        }
    })
}

#[test]
fn new_behaviour() {
    let local_keys = Keypair::generate_ed25519();
    let config = BehaviourConfig::default();
    let swarm = task::block_on(P2PNetworkBehaviour::<String, String>::init_swarm(
        local_keys.clone(),
        config,
    ))
    .expect("Failed to init swarm.");
    assert_eq!(
        &PeerId::from_public_key(local_keys.public()),
        Swarm::local_peer_id(&swarm)
    );
    assert!(swarm.get_all_peers().is_empty());
}

#[test]
fn add_peer() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    let peer_id = PeerId::random();
    let addr = mock_addr();
    swarm.add_peer_addr(peer_id, addr.clone());
    assert!(swarm.get_peer_addr(&peer_id).is_some());
    assert!(swarm.get_all_peers().contains(&&peer_id));
    let peer_addrs = swarm.remove_peer(&peer_id);
    assert!(peer_addrs.is_some() && peer_addrs.expect("No address for peer known.").contains(&addr));
    assert!(swarm.get_peer_addr(&peer_id).is_none());
    assert!(!swarm.get_all_peers().contains(&&peer_id));
}

#[test]
fn listen_addr() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8085".parse().expect("Invalid Multiaddress.");
    let listener_id = Swarm::listen_on(&mut swarm, listen_addr.clone()).expect("Listening to swarm failed.");
    let actual_addr = start_listening(&mut swarm).expect("Start listening failed.");
    assert_eq!(listen_addr, actual_addr);
    Swarm::remove_listener(&mut swarm, listener_id).expect("No listener with this id.");
    assert!(!Swarm::listeners(&swarm).any(|addr| addr == &listen_addr));
}

#[test]
fn zeroed_addr() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    // empty ip and port
    let mut listen_addr = "/ip4/0.0.0.0/tcp/0"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = Swarm::listen_on(&mut swarm, listen_addr.clone()).expect("Listening to swarm failed.");
    let mut actual_addr = start_listening(&mut swarm).expect("Start listening failed.");
    // ip and port should both not be zero
    assert_ne!(
        listen_addr.pop().expect("Missing listener port."),
        actual_addr.pop().expect("Missing listener port.")
    );
    assert_ne!(
        listen_addr.pop().expect("Missing listener ipv4 address."),
        actual_addr.pop().expect("Missing listener ipv4 address.")
    );
    Swarm::remove_listener(&mut swarm, listener).expect("No listener with this ID.");

    // empty ip
    let mut listen_addr = "/ip4/0.0.0.0/tcp/8086"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = Swarm::listen_on(&mut swarm, listen_addr.clone()).expect("Listening to swarm failed.");
    let mut actual_addr = start_listening(&mut swarm).expect("Start listening failed.");
    // port should be the same
    assert_eq!(
        listen_addr.pop().expect("Missing listener port."),
        actual_addr.pop().expect("Missing listener port.")
    );
    // ip should not be zero
    assert_ne!(
        listen_addr.pop().expect("Missing listener ipv4 address."),
        actual_addr.pop().expect("Missing listener ipv4 address.")
    );
    Swarm::remove_listener(&mut swarm, listener).expect("No listener with this ID.");

    // empty port
    let mut listen_addr = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = Swarm::listen_on(&mut swarm, listen_addr.clone()).expect("Listening to swarm failed.");
    let mut actual_addr = start_listening(&mut swarm).expect("Start listening failed.");
    // port should not be zero
    assert_ne!(
        listen_addr.pop().expect("Missing listener port."),
        actual_addr.pop().expect("Missing listener port.")
    );
    // ip should be the same
    assert_eq!(
        listen_addr.pop().expect("Missing listener ipv4 address."),
        actual_addr.pop().expect("Missing listener ipv4 address.")
    );
    Swarm::remove_listener(&mut swarm, listener).expect("No listener with this ID.");
}

#[test]
fn request_response() {
    let mut swarm_a = mock_swarm::<Request, Response>();
    let peer_a_id = *Swarm::local_peer_id(&swarm_a);
    Swarm::listen_on(
        &mut swarm_a,
        "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."),
    )
    .expect("Listening to swarm failed.");

    let mut swarm_b = mock_swarm::<Request, Response>();
    let local_peer_id = *Swarm::local_peer_id(&swarm_b);

    let addr_a = start_listening(&mut swarm_a).expect("Start listening failed.");

    let remote_handle = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm_a.next().await {
                match boxed_event.deref().clone() {
                    P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request: Request::Ping,
                    } => {
                        assert_eq!(peer_id, local_peer_id);
                        swarm_a
                            .send_response(request_id, Response::Pong)
                            .expect("Sending response failed.");
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id: _ } => {
                        assert_eq!(peer_id, local_peer_id);
                        std::thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                    _ => return Err(()),
                }
            }
        }
    });

    establish_connection(peer_a_id, addr_a, &mut swarm_b).expect("Failed to establish a connection.");
    swarm_b.send_request(&peer_a_id, Request::Ping);
    let local_handle = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm_b.next().await {
                if let P2PReqResEvent::Res {
                    peer_id,
                    request_id: _,
                    response: Response::Pong,
                } = boxed_event.deref().clone()
                {
                    assert_eq!(peer_id, peer_a_id);
                    std::thread::sleep(Duration::from_millis(50));
                    return Ok(());
                } else {
                    return Err(());
                }
            }
        }
    });
    let (a, b) = task::block_on(async { future::join(local_handle, remote_handle).await });
    a.and(b).expect("Invalid event received from swarm.");
}

#[test]
fn identify_event() {
    let mut swarm_a = mock_swarm::<Empty, Empty>();
    let peer_a_id = *Swarm::local_peer_id(&swarm_a);
    let listener_id_a = Swarm::listen_on(
        &mut swarm_a,
        "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."),
    )
    .expect("Listening to swarm failed.");
    let addr_a = start_listening(&mut swarm_a).expect("Start listening failed.");
    let mut swarm_b = mock_swarm::<Empty, Empty>();
    let peer_b_id = *Swarm::local_peer_id(&swarm_b);
    let listener_id_b = Swarm::listen_on(
        &mut swarm_b,
        "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."),
    )
    .expect("Listening to swarm failed.");
    let addr_b = start_listening(&mut swarm_b).expect("Start listening failed.");

    Swarm::dial_addr(&mut swarm_a, addr_b.clone()).expect("Failed to dial address.");
    let handle_a = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        while !sent || !received {
            if let SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) = swarm_a.next_event().await {
                match boxed_event.deref().clone() {
                    P2PIdentifyEvent::Received {
                        peer_id,
                        info,
                        observed_addr: _,
                    } => {
                        if peer_id == peer_b_id {
                            assert_eq!(PeerId::from_public_key(info.clone().public_key), peer_id);
                            assert!(info.listen_addrs.contains(&addr_b));
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == peer_b_id {
                            sent = true;
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    P2PIdentifyEvent::Error { peer_id: _, error } => return Err(error),
                }
            }
        }
        Swarm::remove_listener(&mut swarm_a, listener_id_a).expect("No listener with this id.");
        Ok(())
    });

    let handle_b = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        while !sent || !received {
            if let SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) = swarm_b.next_event().await {
                match boxed_event.deref().clone() {
                    P2PIdentifyEvent::Received {
                        peer_id,
                        info,
                        observed_addr: _,
                    } => {
                        if peer_id == peer_a_id {
                            assert_eq!(PeerId::from_public_key(info.clone().public_key), peer_id);
                            assert!(info.listen_addrs.contains(&addr_a));
                            let known_addr = swarm_b.get_peer_addr(&peer_a_id).expect("No address known for peer.");
                            for addr in info.listen_addrs {
                                assert!(known_addr.contains(&addr));
                            }
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == peer_a_id {
                            sent = true;
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    P2PIdentifyEvent::Error { peer_id: _, error } => return Err(error),
                }
            }
        }
        Swarm::remove_listener(&mut swarm_b, listener_id_b).expect("No listener with this id.");
        Ok(())
    });
    let (a, b) = task::block_on(async { future::join(handle_a, handle_b).await });
    a.and(b).expect("Invalid event received from swarm.");
}

#[test]
fn relay() {
    let mut swarm = mock_swarm::<RequestEnvelope<Request>, Response>();
    let relay_peer_id = *Swarm::local_peer_id(&swarm);
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening to swarm failed.");
    let relay_addr = start_listening(&mut swarm).expect("Start listening failed.");
    // start relay peer
    let relay_handle = task::spawn(async move {
        let mut original_request = None;
        let mut relayed_request = None;
        let mut source_peer = None;
        let mut target_peer = None;
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm.next().await {
                match boxed_event.deref().clone() {
                    P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request,
                    } => {
                        let source = PeerId::from_str(&request.source).expect("Invalid PeerId.");
                        assert_eq!(peer_id, source);
                        let target = PeerId::from_str(&request.target).expect("Invalid PeerId.");
                        let relayed_req_id = swarm.send_request(&target, request);
                        relayed_request = Some(relayed_req_id);
                        original_request = Some(request_id);
                        source_peer = Some(source);
                        target_peer = Some(target);
                    }
                    P2PReqResEvent::Res {
                        peer_id,
                        request_id,
                        response,
                    } => {
                        assert_eq!(peer_id, target_peer.expect("No target peer known."));
                        assert_eq!(request_id, relayed_request.expect("No relayed request known."));
                        swarm
                            .send_response(original_request.expect("No original request known."), response)
                            .expect("Sending response failed.");
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id } => {
                        assert_eq!(peer_id, source_peer.expect("No source peer known."));
                        assert_eq!(request_id, original_request.expect("No original request known."));
                        std::thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                    _error => return Err(()),
                }
            }
        }
    });

    let mut swarm_a = mock_swarm::<RequestEnvelope<Request>, Response>();
    let peer_a_id = *Swarm::local_peer_id(&swarm_a);
    establish_connection(relay_peer_id, relay_addr.clone(), &mut swarm_a).expect("Failed to establish a connection.");

    let mut swarm_b = mock_swarm::<RequestEnvelope<Request>, Response>();
    let peer_b_id = *Swarm::local_peer_id(&swarm_b);
    establish_connection(relay_peer_id, relay_addr, &mut swarm_b).expect("Failed to establish a connection.");

    // start peer a to send a message to peer b
    let handle_a = task::spawn(async move {
        let envelope = RequestEnvelope {
            source: peer_a_id.to_string(),
            message: Request::Ping,
            target: peer_b_id.to_string(),
        };
        swarm_a.send_request(&relay_peer_id, envelope);
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm_a.next().await {
                if let P2PReqResEvent::Res {
                    peer_id,
                    request_id: _,
                    response: _,
                } = boxed_event.deref().clone()
                {
                    assert_eq!(peer_id, relay_peer_id);
                    std::thread::sleep(Duration::from_millis(50));
                    return Ok(());
                } else {
                    return Err(());
                }
            }
        }
    });

    // start peer b to respond to message from peer a
    let handle_b = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm_b.next().await {
                match boxed_event.deref().clone() {
                    P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request:
                            RequestEnvelope {
                                source,
                                message: _,
                                target,
                            },
                    } => {
                        assert_eq!(peer_id, relay_peer_id);
                        assert_eq!(source, peer_a_id.to_string());
                        assert_eq!(target, peer_b_id.to_string());
                        swarm_b
                            .send_response(request_id, Response::Pong)
                            .expect("Sending response failed.");
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id: _ } => {
                        assert_eq!(peer_id, relay_peer_id);
                        std::thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                    _ => return Err(()),
                }
            }
        }
    });
    let (a, b, relay) = task::block_on(async { future::join3(handle_a, handle_b, relay_handle).await });
    a.and(b).and(relay).expect("Invalid event received from swarm.");
}

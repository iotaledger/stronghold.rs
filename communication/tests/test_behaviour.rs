// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication::{
    behaviour::{BehaviourConfig, MessageEvent, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::{Keypair, Multiaddr, PeerId, Protocol, Swarm, SwarmEvent},
};
use core::time::Duration;
use futures::{
    executor::LocalPool,
    future::{self, FutureExt},
    task::Spawn,
};
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
                SwarmEvent::ListenerClosed { .. } | SwarmEvent::ListenerError { .. } => return None,
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
    Swarm::dial_addr(swarm, target_addr.clone()).expect("Failed to dial address.");
    task::block_on(async {
        loop {
            let event = swarm.next_event().await;
            match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_id => {
                    return Some(());
                }
                SwarmEvent::ConnectionClosed { .. } => panic!(target_addr),
                SwarmEvent::UnreachableAddr {
                    attempts_remaining: 0, ..
                } => panic!(target_addr),
                SwarmEvent::UnknownPeerUnreachableAddr { .. } => panic!(target_addr),
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
                match *boxed_event {
                    P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request: Request::Ping,
                    } => {
                        assert_eq!(peer_id, local_peer_id);
                        swarm_a
                            .send_response(&request_id, Response::Pong)
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
                } = *boxed_event
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
                match *boxed_event {
                    P2PIdentifyEvent::Received {
                        peer_id,
                        info,
                        observed_addr: _,
                    } => {
                        if peer_id == peer_b_id {
                            assert_eq!(PeerId::from_public_key(info.public_key), peer_id);
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
                match *boxed_event {
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
    let mut pool = LocalPool::new();

    let mut src_swarm = mock_swarm::<Request, Response>();
    let mut dst_swarm = mock_swarm::<Request, Response>();
    let mut relay_swarm = mock_swarm::<Request, Response>();

    let src_peer_id = Swarm::local_peer_id(&src_swarm).clone();
    let dst_peer_id = Swarm::local_peer_id(&dst_swarm).clone();
    let relay_peer_id = Swarm::local_peer_id(&relay_swarm).clone();

    let relay_addr = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::new(127, 0, 0, 1)))
        .with(Protocol::Tcp(8081));
    let dst_listen_addr_via_relay = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id.into()))
        .with(Protocol::P2pCircuit);
    let dst_addr_via_relay = dst_listen_addr_via_relay
        .clone()
        .with(Protocol::P2p(dst_peer_id.into()));

    Swarm::listen_on(&mut relay_swarm, relay_addr.clone()).unwrap();
    pool.spawner()
        .spawn_obj(
            async move {
                loop {
                    relay_swarm.next_event().await;
                }
            }
            .boxed()
            .into(),
        )
        .unwrap();

    Swarm::listen_on(&mut dst_swarm, dst_listen_addr_via_relay.clone()).unwrap();

    pool.run_until(async {
        // Destination Node dialing Relay.
        match dst_swarm.next_event().await {
            SwarmEvent::Dialing(peer_id) => assert_eq!(peer_id, relay_peer_id),
            e => panic!("{:?}", e),
        }

        // Destination Node establishing connection to Relay.
        match dst_swarm.next_event().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                assert_eq!(peer_id, relay_peer_id);
            }
            e => panic!("{:?}", e),
        }

        // Destination Node reporting listen address via relay.
        loop {
            match dst_swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) if addr == dst_listen_addr_via_relay => break,
                SwarmEvent::Behaviour(_) => {}
                e => panic!("{:?}", e),
            }
        }

        let dst = async move {
            // Destination Node receiving connection from Source Node via Relay.
            loop {
                match dst_swarm.next_event().await {
                    SwarmEvent::IncomingConnection { send_back_addr, .. } => {
                        assert_eq!(send_back_addr, Protocol::P2p(src_peer_id.clone().into()).into());
                        break;
                    }
                    SwarmEvent::Behaviour(_) => {}
                    e => panic!("{:?}", e),
                }
            }

            // Destination Node establishing connection from Source Node via Relay.
            loop {
                match dst_swarm.next_event().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == src_peer_id => {
                        break;
                    }
                    SwarmEvent::Behaviour(_) => {}
                    e => panic!("{:?}", e),
                }
            }

            // Destination Node waiting for Request from Source Node via Relay.
            loop {
                match dst_swarm.next_event().await {
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed)) => {
                        if let P2PReqResEvent::Req {
                            peer_id, request_id, ..
                        } = *boxed
                        {
                            if peer_id == src_peer_id {
                                dst_swarm
                                    .send_response(&request_id, Response::Pong)
                                    .expect("Failed to send response");
                                break;
                            }
                        }
                    }
                    e => panic!("{:?}", e),
                }
            }

            // Destination Node waiting for Ping from Source Node via Relay.
            loop {
                match dst_swarm.next_event().await {
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed)) => {
                        if let P2PReqResEvent::ResSent { peer_id, .. } = *boxed {
                            if peer_id == src_peer_id {
                                break;
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { .. } => {}
                    e => panic!("{:?}", e),
                }
            }
        };

        Swarm::dial_addr(&mut src_swarm, dst_addr_via_relay).unwrap();
        let src = async move {
            // Source Node dialing Relay to connect to Destination Node.
            match src_swarm.next_event().await {
                SwarmEvent::Dialing(peer_id) if peer_id == relay_peer_id => {}
                e => panic!("{:?}", e),
            }

            // Source Node establishing connection to Relay to connect to Destination Node.
            match src_swarm.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => {}
                e => panic!("{:?}", e),
            }

            // Source Node establishing connection to destination node via Relay.
            loop {
                match src_swarm.next_event().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == dst_peer_id => break,
                    SwarmEvent::Behaviour(_) => {}
                    e => panic!("{:?}", e),
                }
            }
            src_swarm.send_request(&dst_peer_id, Request::Ping);

            // Source Node waiting for response from destination node.
            loop {
                match src_swarm.next_event().await {
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed)) => {
                        if let P2PReqResEvent::Res { peer_id, .. } = *boxed {
                            if peer_id == dst_peer_id {
                                break;
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { .. } => {}
                    e => panic!("{:?}", e),
                }
            }
        };

        futures::future::join(dst, src).await
    });
}

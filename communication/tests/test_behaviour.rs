// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication::{
    behaviour::{BehaviourConfig, MessageEvent, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::{Keypair, Multiaddr, PeerId, Protocol, Swarm, SwarmEvent},
};
use futures::future;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, time::Duration};

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
    let config = BehaviourConfig::new(None, Some(std::time::Duration::from_secs(30)), None, None);
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
) {
    swarm.dial_addr(target_addr.clone()).expect("Failed to dial address.");
    task::block_on(async {
        loop {
            let event = swarm.next_event().await;
            match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_id => break,
                SwarmEvent::ConnectionClosed { .. } => panic!("{:?}", target_addr),
                SwarmEvent::UnreachableAddr {
                    attempts_remaining: 0, ..
                } => panic!("{:?}", target_addr),
                SwarmEvent::UnknownPeerUnreachableAddr { .. } => panic!("{:?}", target_addr),
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
    assert_eq!(&PeerId::from_public_key(local_keys.public()), swarm.local_peer_id());
    assert!(swarm.behaviour().get_all_peers().is_empty());
}

#[test]
fn add_peer() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    let peer_id = PeerId::random();
    let addr = mock_addr();
    swarm.behaviour_mut().add_peer_addr(peer_id, addr.clone());
    assert!(swarm.behaviour().get_peer_addr(&peer_id).is_some());
    assert!(swarm.behaviour().get_all_peers().contains(&&peer_id));
    let peer_addrs = swarm.behaviour_mut().remove_peer(&peer_id);
    assert!(peer_addrs.is_some() && peer_addrs.expect("No address for peer known.").contains(&addr));
    assert!(swarm.behaviour().get_peer_addr(&peer_id).is_none());
    assert!(!swarm.behaviour().get_all_peers().contains(&&peer_id));
}

#[test]
fn listen_addr() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8085".parse().expect("Invalid Multiaddress.");
    let listener_id = swarm
        .listen_on(listen_addr.clone())
        .expect("Listening to swarm failed.");
    let actual_addr = start_listening(&mut swarm).expect("Start listening failed.");
    assert_eq!(listen_addr, actual_addr);
    swarm.remove_listener(listener_id).expect("No listener with this id.");
    assert!(!swarm.listeners().any(|addr| addr == &listen_addr));
}

#[test]
fn zeroed_addr() {
    let mut swarm = mock_swarm::<Empty, Empty>();
    // empty ip and port
    let mut listen_addr = "/ip4/0.0.0.0/tcp/0"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = swarm
        .listen_on(listen_addr.clone())
        .expect("Listening to swarm failed.");
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
    swarm.remove_listener(listener).expect("No listener with this ID.");

    // empty ip
    let mut listen_addr = "/ip4/0.0.0.0/tcp/8086"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = swarm
        .listen_on(listen_addr.clone())
        .expect("Listening to swarm failed.");
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
    swarm.remove_listener(listener).expect("No listener with this ID.");

    // empty port
    let mut listen_addr = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .expect("Invalid Multiaddress.");
    let listener = swarm
        .listen_on(listen_addr.clone())
        .expect("Listening to swarm failed.");
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
    swarm.remove_listener(listener).expect("No listener with this ID.");
}

#[test]
fn request_response() {
    let mut swarm_a = mock_swarm::<Request, Response>();
    let peer_a_id = *swarm_a.local_peer_id();
    swarm_a
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening to swarm failed.");

    let mut swarm_b = mock_swarm::<Request, Response>();
    let peer_b_id = *swarm_b.local_peer_id();

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
                        assert_eq!(peer_id, peer_b_id);
                        swarm_a
                            .behaviour_mut()
                            .send_response(&request_id, Response::Pong)
                            .expect("Sending response failed.");
                    }
                    P2PReqResEvent::ResSent { peer_id, .. } => {
                        assert_eq!(peer_id, peer_b_id);
                        break;
                    }
                    e => panic!("{:?}", e),
                }
            }
        }

        // wait for connection to b to close
        loop {
            let event = swarm_a.next_event().await;
            match event {
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    assert_eq!(peer_id, peer_b_id);
                    break;
                }
                e => panic!("{:?}", e),
            }
        }
    });

    establish_connection(peer_a_id, addr_a, &mut swarm_b);
    swarm_b.behaviour_mut().send_request(&peer_a_id, Request::Ping);
    let local_handle = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = swarm_b.next().await {
                if let P2PReqResEvent::Res {
                    peer_id,
                    response: Response::Pong,
                    ..
                } = *boxed_event
                {
                    assert_eq!(peer_id, peer_a_id);
                    break;
                } else {
                    panic!("{:?}", *boxed_event);
                }
            }
        }
    });
    task::block_on(async { future::join(local_handle, remote_handle).await });
}

#[test]
fn identify_event() {
    let mut swarm_a = mock_swarm::<Empty, Empty>();
    let peer_a_id = *swarm_a.local_peer_id();
    let listener_id_a = swarm_a
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening to swarm failed.");
    let addr_a = start_listening(&mut swarm_a).expect("Start listening failed.");
    let mut swarm_b = mock_swarm::<Empty, Empty>();
    let peer_b_id = *swarm_b.local_peer_id();
    let listener_id_b = swarm_b
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening to swarm failed.");
    let addr_b = start_listening(&mut swarm_b).expect("Start listening failed.");

    swarm_a.dial_addr(addr_b.clone()).expect("Failed to dial address.");
    let handle_a = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        loop {
            match swarm_a.next_event().await {
                SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) => match *boxed_event {
                    P2PIdentifyEvent::Received { peer_id, info, .. } => {
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
                    P2PIdentifyEvent::Pushed { .. } => {}
                    P2PIdentifyEvent::Error { error, .. } => panic!("{:?}", error),
                },
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    assert_eq!(peer_id, peer_b_id);
                    break;
                }
                SwarmEvent::NewListenAddr(_)
                | SwarmEvent::IncomingConnection { .. }
                | SwarmEvent::ConnectionEstablished { .. } => {}
                e => panic!("{:?}", e),
            }
        }
        assert!(sent && received);
        swarm_a
            .remove_listener(listener_id_a)
            .expect("No listener with this id.");
    });

    let handle_b = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        loop {
            match swarm_b.next_event().await {
                SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) => match *boxed_event {
                    P2PIdentifyEvent::Received { peer_id, info, .. } => {
                        if peer_id == peer_a_id {
                            assert_eq!(PeerId::from_public_key(info.public_key), peer_id);
                            assert!(info.listen_addrs.contains(&addr_a));
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == peer_a_id {
                            sent = true;
                        }
                    }
                    P2PIdentifyEvent::Pushed { .. } => {}
                    P2PIdentifyEvent::Error { error, .. } => panic!("{:?}", error),
                },
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    assert_eq!(peer_id, peer_a_id);
                    break;
                }
                SwarmEvent::NewListenAddr(_)
                | SwarmEvent::IncomingConnection { .. }
                | SwarmEvent::ConnectionEstablished { .. } => {}
                e => panic!("{:?}", e),
            }
        }
        assert!(sent && received);
        swarm_b
            .remove_listener(listener_id_b)
            .expect("No listener with this id.");
    });
    task::block_on(async { future::join(handle_a, handle_b).await });
}

#[test]
fn relay() {
    let mut swarm = mock_swarm::<Request, Response>();
    let relay_peer_id = *swarm.local_peer_id();
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening to swarm failed.");

    let relay_addr = start_listening(&mut swarm).expect("Start listening failed.");

    // start relay peer
    task::spawn(async move {
        loop {
            swarm.next().await;
        }
    });

    let mut swarm_a = mock_swarm::<Request, Response>();
    let peer_a_id = *swarm_a.local_peer_id();

    let mut swarm_b = mock_swarm::<Request, Response>();
    let peer_b_id = *swarm_b.local_peer_id();
    let relayed_addr_b = relay_addr
        .with(Protocol::P2p(relay_peer_id.into()))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(peer_b_id.into()));
    let relayed_addr_b_clone = relayed_addr_b.clone();

    // wait for peer b to connect to relay and start listening
    task::block_on(async {
        swarm_b
            .listen_on(relayed_addr_b_clone.clone())
            .expect("Start listening failed.");

        // connect to relay
        loop {
            match swarm_b.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => break,
                SwarmEvent::Dialing(peer_id) if peer_id == relay_peer_id => {}
                e => panic!("{:?}", e),
            }
        }

        loop {
            match swarm_b.next_event().await {
                SwarmEvent::NewListenAddr(addr) if addr == relayed_addr_b_clone => break,
                e => panic!("{:?}", e),
            }
        }
    });

    // start peer a to send a message to peer b
    let handle_a = task::spawn(async move {
        swarm_a.dial_addr(relayed_addr_b).expect("Failed to dial address.");
        // Connect to relay
        loop {
            match swarm_a.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => break,
                SwarmEvent::Dialing(peer_id) if peer_id == relay_peer_id => {}
                e => panic!("{:?}", e),
            }
        }

        // Connect to peer b
        loop {
            match swarm_a.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b_id => break,
                SwarmEvent::Dialing(peer_id) if peer_id == relay_peer_id => {}
                SwarmEvent::Behaviour(P2PEvent::Identify(_)) => {}
                e => panic!("{:?}", e),
            }
        }

        swarm_a.behaviour_mut().send_request(&peer_b_id, Request::Ping);

        // Wait for response from b
        loop {
            match swarm_a.next().await {
                P2PEvent::RequestResponse(boxed_event) => {
                    if let P2PReqResEvent::Res { peer_id, .. } = *boxed_event {
                        assert_eq!(peer_id, peer_b_id);
                        break;
                    } else {
                        panic!("{:?}", *boxed_event);
                    }
                }
                P2PEvent::Identify(_) => {}
                // _ => {},
                e => panic!("{:?}", e),
            }
        }
    });

    let handle_b = task::spawn(async move {
        // Connection from peer a
        loop {
            match swarm_b.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_a_id => break,
                SwarmEvent::IncomingConnection { .. } => {}
                SwarmEvent::Behaviour(P2PEvent::Identify(_)) => {}
                e => panic!("{:?}", e),
            }
        }

        // wait for request from peer a
        loop {
            match swarm_b.next().await {
                P2PEvent::RequestResponse(boxed_event) => {
                    if let P2PReqResEvent::Req {
                        peer_id, request_id, ..
                    } = *boxed_event
                    {
                        assert_eq!(peer_id, peer_a_id);
                        swarm_b
                            .behaviour_mut()
                            .send_response(&request_id, Response::Pong)
                            .expect("Sending response failed.");
                        break;
                    } else {
                        panic!("{:?}", *boxed_event);
                    }
                }
                P2PEvent::Identify(_) => {}
                // _ => {}
                e => panic!("{:?}", e),
            }
        }

        // wait for response to be send
        loop {
            match swarm_b.next().await {
                P2PEvent::RequestResponse(boxed_event) => {
                    if let P2PReqResEvent::ResSent { peer_id, .. } = *boxed_event {
                        assert_eq!(peer_id, peer_a_id);
                        break;
                    } else {
                        panic!("{:?}", *boxed_event);
                    }
                }
                // _ => {}
                e => panic!("{:?}", e),
            }
        }

        // wait for connection to a to close
        loop {
            let event = swarm_b.next_event().await;
            match event {
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    assert_eq!(peer_id, peer_a_id);
                    break;
                }
                e => panic!("{:?}", e),
            }
        }
    });
    task::block_on(async { future::join(handle_a, handle_b).await });
}

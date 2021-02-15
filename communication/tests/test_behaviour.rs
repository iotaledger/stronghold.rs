// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use core::{ops::Deref, time::Duration};
use futures::future;
use serde::{Deserialize, Serialize};
use stronghold_communication::{
    behaviour::{BehaviourConfig, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::{Keypair, Multiaddr, PeerId, Swarm, SwarmEvent},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
}

fn mock_swarm() -> Swarm<P2PNetworkBehaviour<Request, Response>> {
    let local_keys = Keypair::generate_ed25519();
    let config = BehaviourConfig::default();
    P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config).unwrap()
}

#[test]
#[should_panic]
fn reuse_addr() {
    let mut swarm_a = mock_swarm();
    let listen_addr = "/ip4/127.0.0.1/tcp/8087".parse::<Multiaddr>();
    if listen_addr.is_err() {
        return;
    }
    let listen_addr = listen_addr.unwrap();
    if Swarm::listen_on(&mut swarm_a, listen_addr.clone()).is_err() {
        return;
    }
    let actual_addr = task::block_on(async {
        loop {
            match swarm_a.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return Some(addr),
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                }
                | SwarmEvent::ListenerError { error: _ } => return None,
                _ => {}
            }
        }
    });
    if actual_addr.is_none() {
        return;
    }

    // set second swarm to listen to same address
    let mut swarm_b = mock_swarm();
    Swarm::listen_on(&mut swarm_b, listen_addr).unwrap();
}

#[test]
fn reuse_port() {
    let mut swarm = mock_swarm();
    let listen_addr = "/ip4/127.0.0.2/tcp/8088".parse::<Multiaddr>().unwrap();
    Swarm::listen_on(&mut swarm, listen_addr.clone()).unwrap();
    task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) => {
                    assert_eq!(listen_addr, addr);
                    break;
                }
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });
    // set second swarm to listen to same address
    let mut swarm = mock_swarm();
    let listen_addr = "/ip4/127.0.0.1/tcp/8088".parse::<Multiaddr>().unwrap();
    Swarm::listen_on(&mut swarm, listen_addr.clone()).unwrap();
    task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) => {
                    assert_eq!(listen_addr, addr);
                    break;
                }
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });
}

#[test]
fn request_response() {
    let mut remote = mock_swarm();
    Swarm::listen_on(&mut remote, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let remote_peer_id = *Swarm::local_peer_id(&remote);
    let remote_addr = task::block_on(async {
        loop {
            match remote.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                }
                | SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });

    let mut local = mock_swarm();
    let local_peer_id = *Swarm::local_peer_id(&local);

    let remote_handle = task::spawn(async move {
        loop {
            match remote.next_event().await {
                SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                    if let P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request: Request::Ping,
                    } = boxed_event.deref().clone()
                    {
                        assert_eq!(peer_id, local_peer_id);
                        remote.send_response(Response::Pong, request_id).unwrap();
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                    cause: _,
                } => {
                    assert_eq!(peer_id, local_peer_id);
                    return;
                }
                SwarmEvent::UnreachableAddr {
                    peer_id: _,
                    address: _,
                    error: _,
                    attempts_remaining: 0,
                }
                | SwarmEvent::UnknownPeerUnreachableAddr { address: _, error: _ } => panic!(),
                _ => {}
            }
        }
    });

    Swarm::dial_addr(&mut local, remote_addr).unwrap();
    let local_handle = task::spawn(async move {
        loop {
            match local.next_event().await {
                SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                    if let P2PReqResEvent::Res {
                        peer_id,
                        request_id: _,
                        response: Response::Pong,
                    } = boxed_event.deref().clone()
                    {
                        assert_eq!(peer_id, remote_peer_id);
                        return;
                    }
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                } => {
                    assert_eq!(peer_id, remote_peer_id);
                    local.send_request(&remote_peer_id, Request::Ping);
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
                | SwarmEvent::UnknownPeerUnreachableAddr { address: _, error: _ } => panic!(),
                _ => {}
            }
        }
    });
    task::block_on(async {
        future::join(local_handle, remote_handle).await;
    });
}

#[test]
fn identify_event() {
    let mut remote = mock_swarm();
    let remote_peer_id = *Swarm::local_peer_id(&remote);
    let remote_listener_id = Swarm::listen_on(&mut remote, "/ip4/127.0.0.6/tcp/0".parse().unwrap()).unwrap();
    let remote_addr = task::block_on(async {
        loop {
            match remote.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                }
                | SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });

    let mut local = mock_swarm();
    let local_peer_id = *Swarm::local_peer_id(&local);
    let local_listener_id = Swarm::listen_on(&mut local, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let local_addr = task::block_on(async {
        loop {
            match local.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                }
                | SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });

    let remote_handle = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        while !sent || !received {
            if let SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) = remote.next_event().await {
                match boxed_event.deref().clone() {
                    P2PIdentifyEvent::Received {
                        peer_id,
                        info,
                        observed_addr: _,
                    } => {
                        if peer_id == local_peer_id {
                            assert_eq!(PeerId::from_public_key(info.clone().public_key), peer_id);
                            assert!(info.listen_addrs.contains(&local_addr));
                            let known_addr = remote.get_peer_addr(&local_peer_id).unwrap();
                            for addr in info.listen_addrs {
                                assert!(known_addr.contains(&addr));
                            }
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == local_peer_id {
                            sent = true;
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    P2PIdentifyEvent::Error { peer_id, error: _ } => {
                        if peer_id == local_peer_id {
                            panic!();
                        }
                    }
                }
            }
        }
        Swarm::remove_listener(&mut remote, remote_listener_id).unwrap();
    });

    Swarm::dial_addr(&mut local, remote_addr.clone()).unwrap();
    let local_handle = task::spawn(async move {
        let mut sent = false;
        let mut received = false;
        while !sent || !received {
            if let SwarmEvent::Behaviour(P2PEvent::Identify(boxed_event)) = local.next_event().await {
                match boxed_event.deref().clone() {
                    P2PIdentifyEvent::Received {
                        peer_id,
                        info,
                        observed_addr: _,
                    } => {
                        if peer_id == remote_peer_id {
                            assert_eq!(PeerId::from_public_key(info.clone().public_key), peer_id);
                            assert!(info.listen_addrs.contains(&remote_addr));
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == remote_peer_id {
                            sent = true;
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    P2PIdentifyEvent::Error { peer_id, error: _ } => {
                        if peer_id == remote_peer_id {
                            panic!();
                        }
                    }
                }
            }
        }
        Swarm::remove_listener(&mut local, local_listener_id).unwrap();
    });
    task::block_on(async {
        future::join(local_handle, remote_handle).await;
    });
}

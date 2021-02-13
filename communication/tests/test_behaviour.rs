// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use core::{ops::Deref, str::FromStr, time::Duration};
use futures::future;
use serde::{Deserialize, Serialize};
use std::thread;
use stronghold_communication::{
    behaviour::{P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent},
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
    P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys).unwrap()
}

fn mock_addr() -> Multiaddr {
    Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap()
}

#[test]
fn new_behaviour() {
    let local_keys = Keypair::generate_ed25519();
    let swarm = P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys.clone()).unwrap();
    assert_eq!(
        &PeerId::from_public_key(local_keys.public()),
        Swarm::local_peer_id(&swarm)
    );
    assert!(swarm.get_all_peers().is_empty());
}

#[test]
fn add_peer() {
    let mut swarm = mock_swarm();
    let peer_id = PeerId::random();
    let addr = mock_addr();
    swarm.add_peer(peer_id, addr.clone());
    assert!(swarm.get_peer_addr(&peer_id).is_some());
    assert!(swarm.get_all_peers().contains(&(&peer_id, &addr)));
    assert_eq!(swarm.remove_peer(&peer_id).unwrap(), addr);
    assert!(swarm.get_peer_addr(&peer_id).is_none());
    assert!(!swarm.get_all_peers().contains(&(&peer_id, &addr)));
}

#[test]
fn listen_addr() {
    let mut swarm = mock_swarm();
    let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8085".parse().unwrap();
    let listener_id = Swarm::listen_on(&mut swarm, listen_addr.clone()).unwrap();
    let actual_addr = task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });
    assert_eq!(listen_addr, actual_addr);
    Swarm::remove_listener(&mut swarm, listener_id).unwrap();
    assert!(!Swarm::listeners(&swarm).any(|addr| addr == &listen_addr));
}

#[test]
fn request_response() {
    let mut remote = mock_swarm();
    let listener_id = Swarm::listen_on(&mut remote, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let remote_peer_id = *Swarm::local_peer_id(&remote);
    let remote_addr = task::block_on(async {
        loop {
            match remote.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
                _ => {}
            }
        }
    });
    let remote_addr_clone = remote_addr.clone();

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
                        if peer_id == local_peer_id {
                            remote.send_response(Response::Pong, request_id).unwrap();
                        }
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                    cause: _,
                } => {
                    if peer_id == local_peer_id {
                        Swarm::remove_listener(&mut remote, listener_id).unwrap();
                        return;
                    }
                }
                SwarmEvent::UnreachableAddr {
                    peer_id: _,
                    address,
                    error: _,
                    attempts_remaining: 0,
                } => {
                    if address == remote_addr {
                        panic!();
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error: _ } => {
                    if address == remote_addr {
                        panic!();
                    }
                }

                _ => {}
            }
        }
    });

    Swarm::dial_addr(&mut local, remote_addr_clone.clone()).unwrap();
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
                        if peer_id == remote_peer_id {
                            return;
                        }
                    }
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                } => {
                    if peer_id == remote_peer_id {
                        local.send_request(&remote_peer_id, Request::Ping);
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                    cause: _,
                } => {
                    if peer_id == remote_peer_id {
                        return;
                    }
                }
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    address: _,
                    error: _,
                    attempts_remaining: 0,
                } => {
                    if peer_id == remote_peer_id {
                        panic!();
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error: _ } => {
                    if address == remote_addr_clone {
                        panic!();
                    }
                }
                _ => {}
            }
        }
    });
    task::block_on(async {
        local_handle.await;
        remote_handle.await;
    })
}

#[test]
fn identify_event() {
    let mut remote = mock_swarm();
    let remote_peer_id = *Swarm::local_peer_id(&remote);
    let remote_listener_id = Swarm::listen_on(&mut remote, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let remote_addr = task::block_on(async {
        loop {
            match remote.next_event().await {
                SwarmEvent::NewListenAddr(addr) => return addr,
                SwarmEvent::ListenerClosed {
                    addresses: _,
                    reason: _,
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
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
                } => panic!(),
                SwarmEvent::ListenerError { error: _ } => panic!(),
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
                            received = true;
                        }
                    }
                    P2PIdentifyEvent::Sent { peer_id } => {
                        if peer_id == local_peer_id {
                            sent = true;
                            thread::sleep(Duration::from_millis(50));
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
                            thread::sleep(Duration::from_millis(50));
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

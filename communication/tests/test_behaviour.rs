// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use core::{ops::Deref, str::FromStr, time::Duration};
use futures::future;
use serde::{Deserialize, Serialize};
use stronghold_communication::{
    behaviour::{
        BehaviourConfig, MessageEvent, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent, RequestEnvelope,
    },
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
    swarm: &mut Swarm<P2PNetworkBehaviour<Req, Res>>,
) {
    task::block_on(async {
        loop {
            match swarm.next_event().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: _,
                    num_established: _,
                } => {
                    assert_eq!(peer_id, target_id);
                    break;
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
    let actual_addr = start_listening(&mut swarm_a);
    if actual_addr.is_none() {
        return;
    }

    // set second swarm to listen to same address
    let mut swarm_b = mock_swarm();
    Swarm::listen_on(&mut swarm_b, listen_addr).unwrap();
    start_listening(&mut swarm_b).unwrap();
}

#[test]
fn reuse_port() {
    let mut swarm_a = mock_swarm();
    let listen_addr = "/ip4/127.0.0.1/tcp/8088".parse::<Multiaddr>().unwrap();
    Swarm::listen_on(&mut swarm_a, listen_addr.clone()).unwrap();
    let actual_addr = start_listening(&mut swarm_a).unwrap();
    assert_eq!(listen_addr, actual_addr);

    // set second swarm to listen to same port but different ip
    let mut swarm_b = mock_swarm();
    let listen_addr = "/ip4/127.0.0.2/tcp/8088".parse::<Multiaddr>().unwrap();
    Swarm::listen_on(&mut swarm_b, listen_addr.clone()).unwrap();
    let actual_addr = start_listening(&mut swarm_b).unwrap();
    assert_eq!(listen_addr, actual_addr);
}

#[test]
fn request_response() {
    let mut remote = mock_swarm();
    let remote_peer_id = *Swarm::local_peer_id(&remote);
    Swarm::listen_on(&mut remote, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    let mut local = mock_swarm();
    let local_peer_id = *Swarm::local_peer_id(&local);

    let remote_addr = start_listening(&mut remote).unwrap();

    let remote_handle = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = remote.next().await {
                match boxed_event.deref().clone() {
                    P2PReqResEvent::Req {
                        peer_id,
                        request_id,
                        request: Request::Ping,
                    } => {
                        assert_eq!(peer_id, local_peer_id);
                        remote.send_response(request_id, Response::Pong).unwrap();
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id: _ } => {
                        assert_eq!(peer_id, local_peer_id);
                        std::thread::sleep(Duration::from_millis(50));
                        return;
                    }
                    _ => {}
                }
            }
        }
    });

    Swarm::dial_addr(&mut local, remote_addr).unwrap();
    establish_connection(remote_peer_id, &mut local);
    local.send_request(&remote_peer_id, Request::Ping);
    let local_handle = task::spawn(async move {
        loop {
            if let P2PEvent::RequestResponse(boxed_event) = local.next().await {
                if let P2PReqResEvent::Res {
                    peer_id,
                    request_id: _,
                    response: Response::Pong,
                } = boxed_event.deref().clone()
                {
                    assert_eq!(peer_id, remote_peer_id);
                    std::thread::sleep(Duration::from_millis(50));
                    return;
                } else {
                    panic!();
                }
            }
        }
    });
    task::block_on(async {
        future::join(local_handle, remote_handle).await;
    });
}

#[test]
fn identify_event() {
    let mut swarm_a = mock_swarm();
    let peer_a_id = *Swarm::local_peer_id(&swarm_a);
    let listener_id_a = Swarm::listen_on(&mut swarm_a, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let addr_a = start_listening(&mut swarm_a).unwrap();
    let mut swarm_b = mock_swarm();
    let peer_b_id = *Swarm::local_peer_id(&swarm_b);
    let listener_id_b = Swarm::listen_on(&mut swarm_b, "/ip4/127.0.0.6/tcp/0".parse().unwrap()).unwrap();
    let addr_b = start_listening(&mut swarm_b).unwrap();

    Swarm::dial_addr(&mut swarm_a, addr_b.clone()).unwrap();
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
                    P2PIdentifyEvent::Error { peer_id, error: _ } => {
                        if peer_id == peer_b_id {
                            panic!();
                        }
                    }
                }
            }
        }
        Swarm::remove_listener(&mut swarm_a, listener_id_a).unwrap();
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
                            let known_addr = swarm_b.get_peer_addr(&peer_a_id).unwrap();
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
                    P2PIdentifyEvent::Error { peer_id, error: _ } => {
                        if peer_id == peer_a_id {
                            panic!();
                        }
                    }
                }
            }
        }
        Swarm::remove_listener(&mut swarm_b, listener_id_b).unwrap();
    });
    task::block_on(async {
        future::join(handle_a, handle_b).await;
    });
}

#[test]
fn relay() {
    let config = BehaviourConfig::default();

    let mut swarm = P2PNetworkBehaviour::<RequestEnvelope<Request>, Response>::init_swarm(
        Keypair::generate_ed25519(),
        config.clone(),
    )
    .unwrap();
    let relay_peer_id = *Swarm::local_peer_id(&swarm);
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    let relay_addr = start_listening(&mut swarm).unwrap();
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
                        let source = PeerId::from_str(&request.source).unwrap();
                        assert_eq!(peer_id, source);
                        let target = PeerId::from_str(&request.target).unwrap();
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
                        assert_eq!(peer_id, target_peer.unwrap());
                        assert_eq!(request_id, relayed_request.unwrap());
                        swarm.send_response(original_request.unwrap(), response).unwrap();
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id } => {
                        assert_eq!(peer_id, source_peer.unwrap());
                        assert_eq!(request_id, original_request.unwrap());
                        break;
                    }
                    _error => panic!(),
                }
            }
        }
    });

    let mut swarm_a = P2PNetworkBehaviour::<RequestEnvelope<Request>, Response>::init_swarm(
        Keypair::generate_ed25519(),
        config.clone(),
    )
    .unwrap();
    let peer_a_id = *Swarm::local_peer_id(&swarm_a);
    Swarm::dial_addr(&mut swarm_a, relay_addr.clone()).unwrap();
    establish_connection(relay_peer_id, &mut swarm_a);

    let mut swarm_b =
        P2PNetworkBehaviour::<RequestEnvelope<Request>, Response>::init_swarm(Keypair::generate_ed25519(), config)
            .unwrap();
    let peer_b_id = *Swarm::local_peer_id(&swarm_b);
    Swarm::dial_addr(&mut swarm_b, relay_addr).unwrap();
    establish_connection(relay_peer_id, &mut swarm_b);

    // start peer a to send amessage
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
                    break;
                } else {
                    panic!();
                }
            }
        }
    });

    // start peer a to send amessage
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
                        swarm_b.send_response(request_id, Response::Pong).unwrap();
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id: _ } => {
                        assert_eq!(peer_id, relay_peer_id);
                        std::thread::sleep(Duration::from_millis(50));
                        return;
                    }
                    _ => {}
                }
            }
        }
    });
    task::block_on(async {
        future::join3(handle_a, handle_b, relay_handle).await;
    });
}
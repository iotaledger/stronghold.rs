// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

use communication_refactored::{
    behaviour::{BehaviourEvent, NetBehaviour, NetBehaviourConfig, OutboundFailure},
    firewall::{PermissionValue, RequestPermissions, Rule, RuleDirection, VariantPermission},
    ReceiveRequest, RequestMessage,
};
use futures::{channel::mpsc, executor::LocalPool, future::FutureObj, prelude::*, select, task::Spawn};
use libp2p::{
    core::{identity, transport::Transport, upgrade, Multiaddr, PeerId},
    mdns::{Mdns, MdnsConfig},
    noise::{Keypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
};
use serde::{Deserialize, Serialize};

/// Exercises a simple ping protocol.
#[test]
fn ping_protocol() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let ping = Ping("ping".to_string().into_bytes());
    let pong = Pong("pong".to_string().into_bytes());

    let (peer1_id, mut swarm1) = init_swarm(&mut pool);
    let (peer2_id, mut swarm2) = init_swarm(&mut pool);

    let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    let expected_ping = ping.clone();

    let peer1_future = async move {
        loop {
            match swarm1.next_event().await {
                SwarmEvent::NewListenAddr(addr) => tx.send(addr).await.unwrap(),
                SwarmEvent::Behaviour(BehaviourEvent::Request(ReceiveRequest {
                    peer,
                    request: RequestMessage { data, response_tx, .. },
                    ..
                })) => {
                    assert_eq!(&data, &expected_ping);
                    assert_eq!(&peer, &peer2_id);
                    response_tx.send(pong.clone()).unwrap();
                }
                SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                _ => {}
            }
        }
    };

    let num_pings = 100;

    let peer2_future = async move {
        let mut count = 0u8;
        let addr = rx.next().await.unwrap();
        swarm2.behaviour_mut().add_address(peer1_id, addr.clone());
        let mut response_recv = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        loop {
            select! {
                _ = swarm2.next().fuse() => panic!(),
                _ = response_recv.response_rx.fuse() => {
                    count += 1;
                    if count >= num_pings {
                        return;
                    } else {
                        response_recv = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());
                    }
                }
            }
        }
    };

    spawner.spawn_obj(FutureObj::new(Box::pin(peer1_future))).unwrap();
    pool.run_until(peer2_future);
}

#[test]
fn emits_inbound_connection_closed_failure() {
    let mut pool = LocalPool::new();

    let ping = Ping("ping".to_string().into_bytes());
    let pong = Pong("pong".to_string().into_bytes());

    let (peer1_id, mut swarm1) = init_swarm(&mut pool);
    let (peer2_id, mut swarm2) = init_swarm(&mut pool);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    pool.run_until(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
        swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let response_tx = loop {
            futures::select!(
                event = swarm1.next().fuse() => match event {
                    BehaviourEvent::Request(ReceiveRequest {
                        peer,
                        request: RequestMessage { data, response_tx, .. },
                        ..
                    }) => {
                        assert_eq!(&data, &ping);
                        assert_eq!(&peer, &peer2_id);
                        break response_tx
                    },
                    e => panic!("Peer1: Unexpected event: {:?}", e)
                },
                event = swarm2.next().fuse() => panic!("Peer2: Unexpected event: {:?}", event),
            )
        };

        // Drop swarm 2 in order for the connection between swarm 1 and 2 to close.
        drop(swarm2);

        match swarm1.next_event().await {
            SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == peer2_id => {
                assert!(response_tx.send(pong).is_err());
            }
            e => panic!("Peer1: Unexpected event: {:?}", e),
        }
    });
}

/// We expect the substream to be properly closed when response channel is dropped.
/// Since the ping protocol used here expects a response, the sender considers this
/// early close as a protocol violation which results in the connection being closed.
/// If the substream were not properly closed when dropped, the sender would instead
/// run into a timeout waiting for the response.
#[test]
fn emits_inbound_connection_closed_if_channel_is_dropped() {
    let mut pool = LocalPool::new();
    let ping = Ping("ping".to_string().into_bytes());

    let (peer1_id, mut swarm1) = init_swarm(&mut pool);
    let (peer2_id, mut swarm2) = init_swarm(&mut pool);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    pool.run_until(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
        let mut response_rx = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let event = loop {
            futures::select!(
                event = swarm1.next().fuse() => match event {
                    BehaviourEvent::Request(ReceiveRequest {
                        peer,
                        request: RequestMessage { data, response_tx, .. },
                        ..
                    }) => {
                        assert_eq!(&data, &ping);
                        assert_eq!(&peer, &peer2_id);
                        drop(response_tx);
                        continue;
                    },
                    e => panic!("Peer1: Unexpected event: {:?}", e)
                },
                event = swarm2.next().fuse() => break event,
            )
        };

        match event {
            BehaviourEvent::OutboundFailure {
                peer,
                request_id,
                failure: OutboundFailure::ConnectionClosed,
            } => {
                assert_eq!(peer, peer1_id);
                assert_eq!(request_id, response_rx.request_id);
                assert!(response_rx.response_rx.try_recv().is_err())
            }
            e => panic!("unexpected event from peer 2: {:?}", e),
        };
    });
}

fn init_swarm(pool: &mut LocalPool) -> (PeerId, Swarm<NetBehaviour<Ping, Pong, Ping>>) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer = id_keys.public().into_peer_id();
    let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
    let (relay_transport, relay_behaviour) =
        new_transport_and_behaviour(RelayConfig::default(), TcpConfig::new().nodelay(true));
    let transport = relay_transport
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(YamuxConfig::default())
        .boxed();

    let mut cfg = NetBehaviourConfig::default();
    cfg.firewall.set_default(Rule::allow_all(), RuleDirection::Both);
    let mdns = pool
        .run_until(Mdns::new(MdnsConfig::default()))
        .expect("Failed to create mdns behaviour.");
    let (dummy_tx, _) = mpsc::channel(1);
    let behaviour = NetBehaviour::new(cfg, mdns, relay_behaviour, dummy_tx);
    (peer, Swarm::new(transport, behaviour, peer))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
struct Ping(Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
struct Pong(Vec<u8>);

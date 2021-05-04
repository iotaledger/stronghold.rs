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

use communication_refactored::*;
use futures::{channel::mpsc, prelude::*};
use libp2p::{
    core::{identity, transport::Transport, upgrade, Multiaddr, PeerId},
    mdns::{Mdns, MdnsConfig},
    noise::{Keypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
};
use rand::{self, Rng};
use serde::{Deserialize, Serialize};

/// Exercises a simple ping protocol.
#[test]
fn ping_protocol() {
    let ping = Ping("ping".to_string().into_bytes());
    let pong = Pong("pong".to_string().into_bytes());

    let (peer1_id, mut swarm1) = async_std::task::block_on(init_swarm());
    let (peer2_id, mut swarm2) = async_std::task::block_on(init_swarm());

    let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    let expected_ping = ping.clone();
    let expected_pong = pong.clone();

    let peer1 = async move {
        loop {
            match swarm1.next_event().await {
                SwarmEvent::NewListenAddr(addr) => tx.send(addr).await.unwrap(),
                SwarmEvent::Behaviour(BehaviourEvent::ReceiveRequest {
                    peer,
                    request:
                        Request {
                            message,
                            response_sender,
                            ..
                        },
                    ..
                }) => {
                    assert_eq!(&message, &expected_ping);
                    assert_eq!(&peer, &peer2_id);
                    response_sender.send(pong.clone()).unwrap();
                }
                SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                _ => {}
            }
        }
    };

    let num_pings: u8 = rand::thread_rng().gen_range(1, 100);

    let peer2 = async move {
        let mut count = 0;
        let addr = rx.next().await.unwrap();
        swarm2.behaviour_mut().add_address(&peer1_id, addr.clone());
        let mut response_channel = swarm2.behaviour_mut().send_request(peer1_id, ping.clone()).unwrap();

        loop {
            match swarm2.next().await {
                BehaviourEvent::ReceiveResponse {
                    peer,
                    request_id,
                    result: Ok(()),
                } => {
                    let req_id = *response_channel.request_id();
                    let response = response_channel.try_receive().unwrap().unwrap();
                    count += 1;
                    assert_eq!(&response, &expected_pong);
                    assert_eq!(&peer, &peer1_id);
                    assert_eq!(req_id, request_id);
                    if count >= num_pings {
                        return;
                    } else {
                        response_channel = swarm2.behaviour_mut().send_request(peer1_id, ping.clone()).unwrap();
                    }
                }
                e => panic!("Peer2: Unexpected event: {:?}", e),
            }
        }
    };

    async_std::task::spawn(Box::pin(peer1));
    let () = async_std::task::block_on(peer2);
}

#[test]
fn emits_inbound_connection_closed_failure() {
    let ping = Ping("ping".to_string().into_bytes());
    let pong = Pong("pong".to_string().into_bytes());

    let (peer1_id, mut swarm1) = async_std::task::block_on(init_swarm());
    let (peer2_id, mut swarm2) = async_std::task::block_on(init_swarm());

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    futures::executor::block_on(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(&peer1_id, addr1.clone());
        swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let response_sender = loop {
            futures::select!(
                event = swarm1.next().fuse() => match event {
                    BehaviourEvent::ReceiveRequest { peer, request: Request{message, response_sender, .. }, ..} => {
                        assert_eq!(&message, &ping);
                        assert_eq!(&peer, &peer2_id);
                        break response_sender
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
                assert!(response_sender.send(pong).is_err());
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
    let ping = Ping("ping".to_string().into_bytes());

    let (peer1_id, mut swarm1) = async_std::task::block_on(init_swarm());
    let (peer2_id, mut swarm2) = async_std::task::block_on(init_swarm());

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    futures::executor::block_on(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(&peer1_id, addr1.clone());
        let mut response_receiver = swarm2.behaviour_mut().send_request(peer1_id, ping.clone()).unwrap();

        // Wait for swarm 1 to receive request by swarm 2.
        let event = loop {
            futures::select!(
                            event = swarm1.next().fuse() =>
                            if let BehaviourEvent::ReceiveRequest{ peer, request: Request {message, response_sender, ..}, ..} =
            event {                      assert_eq!(&message, &ping);
                                    assert_eq!(&peer, &peer2_id);
                                    drop(response_sender);
                                continue;
                            },
                            event = swarm2.next().fuse() => break event,
                        )
        };

        match event {
            BehaviourEvent::ReceiveResponse {
                peer,
                request_id,
                result: Err(RecvResponseErr::ConnectionClosed),
            } => {
                assert_eq!(peer, peer1_id);
                assert_eq!(&request_id, response_receiver.request_id());
                assert!(response_receiver.try_receive().is_err())
            }
            e => panic!("unexpected event from peer 2: {:?}", e),
        };
    });
}

async fn init_swarm() -> (PeerId, Swarm<NetBehaviour<Ping, Pong>>) {
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
    let protocols = vec![CommunicationProtocol];
    let cfg = NetBehaviourConfig::default();
    let mdns = Mdns::new(MdnsConfig::default())
        .await
        .expect("Failed to create mdns behaviour.");
    let behaviour = NetBehaviour::new(protocols, cfg, mdns, relay_behaviour);
    (peer, Swarm::new(transport, behaviour, peer))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Ping(Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Pong(Vec<u8>);

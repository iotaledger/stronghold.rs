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
    core::{
        identity,
        muxing::StreamMuxerBox,
        transport::{self, Transport},
        upgrade, Multiaddr, PeerId,
    },
    noise::{Keypair, NoiseConfig, X25519Spec},
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

    let protocols = vec![MessageProtocol];
    let cfg = RequestResponseConfig::default();

    let (peer1_id, trans) = mk_transport();
    let ping_proto1 = RequestResponse::<Ping, Pong>::new(protocols.clone(), cfg.clone());
    let mut swarm1 = Swarm::new(trans, ping_proto1, peer1_id);

    let (peer2_id, trans) = mk_transport();
    let ping_proto2 = RequestResponse::<Ping, Pong>::new(protocols, cfg);
    let mut swarm2 = Swarm::new(trans, ping_proto2, peer2_id);

    let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    let expected_ping = ping.clone();
    let expected_pong = pong.clone();

    let peer1 = async move {
        loop {
            match swarm1.next_event().await {
                SwarmEvent::NewListenAddr(addr) => tx.send(addr).await.unwrap(),
                SwarmEvent::Behaviour(BehaviourEvent {
                    peer_id,
                    event:
                        RequestResponseEvent::ReceiveRequest(Ok(Request {
                            request,
                            response_channel,
                        })),
                    ..
                }) => {
                    assert_eq!(&request, &expected_ping);
                    assert_eq!(&peer_id, &peer2_id);
                    response_channel.send(pong.clone()).unwrap();
                }
                SwarmEvent::Behaviour(BehaviourEvent {
                    peer_id,
                    event: RequestResponseEvent::SendResponse(Ok(..)),
                    ..
                }) => {
                    assert_eq!(&peer_id, &peer2_id);
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
        let mut req_id = swarm2.behaviour_mut().send_request(&peer1_id, ping.clone()).unwrap();

        loop {
            let BehaviourEvent {
                peer_id,
                request_id,
                event,
            } = swarm2.next().await;
            match event {
                RequestResponseEvent::ReceiveResponse(Ok(response)) => {
                    count += 1;
                    assert_eq!(&response, &expected_pong);
                    assert_eq!(&peer_id, &peer1_id);
                    assert_eq!(req_id, request_id);
                    if count >= num_pings {
                        return;
                    } else {
                        req_id = swarm2.behaviour_mut().send_request(&peer1_id, ping.clone()).unwrap();
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

    let protocols = vec![MessageProtocol];
    let cfg = RequestResponseConfig::default();

    let (peer1_id, trans) = mk_transport();
    let ping_proto1 = RequestResponse::<Ping, Pong>::new(protocols.clone(), cfg.clone());
    let mut swarm1 = Swarm::new(trans, ping_proto1, peer1_id);

    let (peer2_id, trans) = mk_transport();
    let ping_proto2 = RequestResponse::<Ping, Pong>::new(protocols, cfg);
    let mut swarm2 = Swarm::new(trans, ping_proto2, peer2_id);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    futures::executor::block_on(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(&peer1_id, addr1.clone());
        swarm2.behaviour_mut().send_request(&peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let _channel = loop {
            futures::select!(
                BehaviourEvent {peer_id, event, ..} = swarm1.next().fuse() => match event {
                    RequestResponseEvent::ReceiveRequest(Ok(Request {request, response_channel})) => {
                        assert_eq!(&request, &ping);
                        assert_eq!(&peer_id, &peer2_id);
                        break response_channel
                    },
                    e => panic!("Peer1: Unexpected event: {:?}", e)
                },
                event = swarm2.next().fuse() => panic!("Peer2: Unexpected event: {:?}", event),
            )
        };

        // Drop swarm 2 in order for the connection between swarm 1 and 2 to close.
        drop(swarm2);

        let BehaviourEvent { event, .. } = swarm1.next().await;

        match event {
            RequestResponseEvent::SendResponse(Err(SendResponseError::ConnectionClosed)) => {}
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

    let protocols = vec![MessageProtocol];
    let cfg = RequestResponseConfig::default();

    let (peer1_id, trans) = mk_transport();
    let ping_proto1 = RequestResponse::<Ping, Pong>::new(protocols.clone(), cfg.clone());
    let mut swarm1 = Swarm::new(trans, ping_proto1, peer1_id);

    let (peer2_id, trans) = mk_transport();
    let ping_proto2 = RequestResponse::<Ping, Pong>::new(protocols, cfg);
    let mut swarm2 = Swarm::new(trans, ping_proto2, peer2_id);

    let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr).unwrap();

    futures::executor::block_on(async move {
        while swarm1.next().now_or_never().is_some() {}
        let addr1 = Swarm::listeners(&swarm1).next().unwrap();

        swarm2.behaviour_mut().add_address(&peer1_id, addr1.clone());
        swarm2.behaviour_mut().send_request(&peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let event = loop {
            futures::select!(
                BehaviourEvent {peer_id, event, ..} = swarm1.next().fuse() =>
                if let RequestResponseEvent::ReceiveRequest(Ok(Request {request, response_channel})) = event {
                     assert_eq!(&request, &ping);
                     assert_eq!(&peer_id, &peer2_id);
                     drop(response_channel);
                    continue;
                },
                BehaviourEvent { event, ..} = swarm2.next().fuse() => {
                    break event;
                },
            )
        };

        match event {
            RequestResponseEvent::ReceiveResponse(Err(ReceiveResponseError::ConnectionClosed)) => {}
            e => panic!("unexpected event from peer 2: {:?}", e),
        };
    });
}

fn mk_transport() -> (PeerId, transport::Boxed<(PeerId, StreamMuxerBox)>) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().into_peer_id();
    let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
    (
        peer_id,
        TcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Ping(Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Pong(Vec<u8>);

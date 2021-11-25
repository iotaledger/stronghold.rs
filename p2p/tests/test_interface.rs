// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::{channel::mpsc, future::join, StreamExt};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use p2p::{
    firewall::FirewallRules, ChannelSinkConfig, EventChannel, ReceiveRequest, StrongholdP2p, StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Request {
    Ping,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Response {
    Pong,
    Other,
}

async fn init_peer() -> (
    mpsc::Receiver<ReceiveRequest<Request, Response>>,
    StrongholdP2p<Request, Response>,
) {
    let (dummy_tx, _) = mpsc::channel(10);
    let (request_channel, rq_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);

    let builder = StrongholdP2pBuilder::new(dummy_tx, request_channel, None)
        .with_connection_timeout(Duration::from_secs(1))
        .with_request_timeout(Duration::from_secs(1))
        .with_firewall_default(FirewallRules::allow_all());
    #[cfg(not(feature = "tcp-transport"))]
    let peer = builder
        .build_with_transport(TokioTcpConfig::new(), |fut| {
            tokio::spawn(fut);
        })
        .await
        .unwrap();
    #[cfg(feature = "tcp-transport")]
    let peer = builder.build().await.unwrap();
    (rq_rx, peer)
}

#[tokio::test]
async fn test_send_req() {
    let (mut bob_request_rx, mut bob) = init_peer().await;
    let bob_id = bob.peer_id();
    let bob_addr = bob
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .unwrap();

    let (_, mut alice) = init_peer().await;

    // Alice adds Bob's address and sends a request.
    alice.add_address(bob_id, bob_addr).await;

    // Alice sends a request.
    let alice_send_req = alice.send_request(bob_id, Request::Ping);

    // Bob receives the request and sends a response.
    let bob_recv_req = async {
        let ReceiveRequest {
            response_tx: bob_response_tx,
            ..
        } = bob_request_rx.next().await.unwrap();
        bob_response_tx.send(Response::Pong).unwrap();
    };

    let (res, ()) = join(alice_send_req, bob_recv_req).await;
    match res {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error: {}", e),
    }

    // Drop Bob, expect bob's incoming-requests channel to close
    drop(bob);
    assert!(bob_request_rx.next().await.is_none());
}

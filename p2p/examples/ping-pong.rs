// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Simple example where Alice sends a Ping to Bob and Bob responds with a Pong.

use futures::{channel::mpsc, future::join, StreamExt};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use p2p::{
    firewall::FirewallRules, ChannelSinkConfig, EventChannel, ReceiveRequest, StrongholdP2p, StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Ping;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Pong;

async fn init_peer() -> (mpsc::Receiver<ReceiveRequest<Ping, Pong>>, StrongholdP2p<Ping, Pong>) {
    let (dummy_tx, _) = mpsc::channel(10);
    let (request_channel, rq_rx) = EventChannel::new(10, ChannelSinkConfig::BufferLatest);

    let builder = StrongholdP2pBuilder::new(dummy_tx, request_channel, None, FirewallRules::allow_all())
        .with_connection_timeout(Duration::from_secs(1))
        .with_request_timeout(Duration::from_secs(1));
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

#[tokio::main]
async fn main() {
    let (mut bob_request_rx, mut bob) = init_peer().await;
    let bob_id = bob.peer_id();
    let bob_addr = bob
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .unwrap();

    let (_, mut alice) = init_peer().await;

    // Alice adds Bob's address.
    alice.add_address(bob_id, bob_addr).await;

    // Alice sends a request.
    let alice_send_req = async {
        println!("[Alice] Sending Ping to Bob.");
        let res = alice.send_request(bob_id, Ping).await;
        println!("[Alice] Result: {:?}.", res);
    };

    // Bob receives the request and sends a response.
    let bob_recv_req = async {
        let ReceiveRequest {
            response_tx: bob_response_tx,
            ..
        } = bob_request_rx.next().await.unwrap();
        println!("[Bob] Received Ping from Alice.");
        bob_response_tx.send(Pong).unwrap();
        println!("[Bob] Sending Pong back to Alice.");
    };

    join(alice_send_req, bob_recv_req).await;
}

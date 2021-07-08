// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication_refactored::{
    firewall::{FirewallConfiguration, PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission},
    ReceiveRequest, ShCommunication, ShCommunicationBuilder,
};
use futures::{channel::mpsc, future::join, StreamExt};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Request {
    Ping,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Response {
    Pong,
    Other,
}

async fn init_comms() -> (
    mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ShCommunication<Request, Response, RequestPermission>,
) {
    let (dummy_tx, _) = mpsc::channel(10);
    let (rq_tx, rq_rx) = mpsc::channel(10);

    let builder = ShCommunicationBuilder::new(dummy_tx, rq_tx, None)
        .with_connection_timeout(Duration::from_secs(1))
        .with_request_timeout(Duration::from_secs(1))
        .with_firewall_config(FirewallConfiguration::allow_all());
    #[cfg(not(feature = "tcp-transport"))]
    let comms = builder.build_with_transport(TokioTcpConfig::new()).await;
    #[cfg(feature = "tcp-transport")]
    let comms = builder.build().await.unwrap();
    (rq_rx, comms)
}

#[tokio::test]
async fn test_send_req() {
    let (mut bob_request_rx, mut bob) = init_comms().await;
    let bob_id = bob.get_peer_id();
    let bob_addr = bob.start_listening(None).await.unwrap();

    let (_, mut alice) = init_comms().await;

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

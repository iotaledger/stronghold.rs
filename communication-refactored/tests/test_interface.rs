// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication_refactored::{
    firewall::{FirewallConfiguration, PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission},
    ReceiveRequest, RequestMessage, ResponseReceiver, ShCommunication, ShCommunicationBuilder,
};
use futures::{channel::mpsc, future::join, StreamExt};
#[cfg(not(feature = "tcp-transport"))]
use libp2p_tcp::TcpConfig;
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

fn init_comms() -> (
    mpsc::Receiver<ReceiveRequest<Request, Response>>,
    ShCommunication<Request, Response, RequestPermission>,
) {
    let (dummy_tx, _) = mpsc::channel(1);
    let (rq_tx, rq_rx) = mpsc::channel(1);

    let builder = ShCommunicationBuilder::new(dummy_tx, rq_tx, None)
        .with_connection_timeout(Duration::from_secs(1))
        .with_request_timeout(Duration::from_secs(1))
        .with_firewall_config(FirewallConfiguration::allow_all());
    #[cfg(not(feature = "tcp-transport"))]
    let comms = task::block_on(builder.build_with_transport(TcpConfig::new()));
    #[cfg(feature = "tcp-transport")]
    let comms = task::block_on(builder.build());
    (rq_rx, comms)
}

#[test]
fn test_send_req() {
    let (mut bob_request_rx, mut bob) = init_comms();
    let bob_id = bob.get_peer_id();
    let bob_addr = task::block_on(bob.start_listening(None)).unwrap();

    let (_, alice) = init_comms();

    alice.add_address(bob_id, bob_addr);
    let ResponseReceiver { response_rx, .. } = alice.send_request(bob_id, Request::Ping);

    let handle_b = task::spawn(async move {
        let ReceiveRequest {
            request: RequestMessage { response_tx, .. },
            ..
        } = bob_request_rx.next().await.unwrap();
        response_tx.send(Response::Pong).unwrap();
    });

    let handle_a = task::spawn(async move {
        response_rx.await.unwrap();
    });

    task::block_on(async {
        join(handle_a, handle_b).await;
        alice.shutdown();
        bob.shutdown();
    })
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication_refactored::{
    firewall::{FirewallConfiguration, PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission},
    CommunicationProtocol, Keypair, NetBehaviourConfig, ReceiveRequest, RequestMessage, ResponseReceiver,
    ShCommunication,
};
use futures::{channel::mpsc, future::join, StreamExt};
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
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
    let id_keys = Keypair::generate_ed25519();
    let cfg = NetBehaviourConfig {
        connection_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        firewall: FirewallConfiguration::allow_all(),
        supported_protocols: smallvec![CommunicationProtocol],
    };
    let (dummy_tx, _) = mpsc::channel(1);
    let (rq_tx, rq_rx) = mpsc::channel(1);
    let comms = task::block_on(ShCommunication::new(id_keys, cfg, dummy_tx, rq_tx, None));
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

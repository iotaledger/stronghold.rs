// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use p2p::{
    assemble_relayed_addr, ChannelSinkConfig, DialErr, EventChannel, ListenErr, ListenRelayErr, PeerId, StrongholdP2p,
    StrongholdP2pBuilder, TransportErr,
};

use futures::channel::mpsc;
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;

fn builder() -> StrongholdP2pBuilder<(), ()> {
    let (dummy_fw_tx, _) = mpsc::channel(10);
    let (dummy_rq_channel, _) = EventChannel::new(10, ChannelSinkConfig::DropLatest);
    StrongholdP2pBuilder::new(dummy_fw_tx, dummy_rq_channel, None)
}

async fn build(builder: StrongholdP2pBuilder<(), ()>) -> StrongholdP2p<(), ()> {
    #[cfg(not(feature = "tcp-transport"))]
    let peer = {
        let executor = |fut| {
            tokio::spawn(fut);
        };
        builder
            .build_with_transport(TokioTcpConfig::new(), executor)
            .await
            .unwrap();
    };
    #[cfg(feature = "tcp-transport")]
    let peer = builder.build().await.unwrap();
    peer
}

#[tokio::test]
async fn mdns_config() {
    // Test both peers mdns disabled.
    let mut dialer_a = build(builder().with_mdns_support(false)).await;
    let mut dialer_b = build(builder().with_mdns_support(false)).await;
    let mut listener_c = build(builder().with_mdns_support(true)).await;
    let c_id = listener_c.peer_id();
    listener_c
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .unwrap();
    let mut listener_d = build(builder().with_mdns_support(true)).await;
    let d_id = listener_d.peer_id();
    listener_d
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .unwrap();

    // Delay so that the mdns peers can get each others addresses.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Test both peers mdns disabled
    let err = dialer_a.connect_peer(c_id).await.unwrap_err();
    assert!(matches!(err, DialErr::NoAddresses), "unexpected error: {}", err);

    // Test dialing peer mdns disabled, listening peer mdns enabled
    let err = dialer_a.connect_peer(d_id).await.unwrap_err();
    assert!(matches!(err, DialErr::NoAddresses), "unexpected error: {}", err);

    // Test dialing peer mdns enabled, listening peer mdns disabled
    let err = dialer_b.connect_peer(c_id).await.unwrap_err();
    assert!(matches!(err, DialErr::NoAddresses), "unexpected error: {}", err);

    // Test both peers mdns enabled
    let err = dialer_b.connect_peer(d_id).await.unwrap_err();
    assert!(matches!(err, DialErr::NoAddresses), "unexpected error: {}", err);
}

#[tokio::test]
async fn relay_config() {
    let mut peer = build(builder().with_relay_support(false)).await;
    let peer_id = peer.peer_id();
    let mut relay = build(builder()).await;
    let relay_id = relay.peer_id();
    let relay_addr = relay
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .unwrap();
    peer.add_address(relay_id, relay_addr.clone()).await;
    let relayed_address = assemble_relayed_addr(peer_id, relay_id, relay_addr.clone());

    // Check normal listening.
    let res = peer.start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap()).await;
    assert!(res.is_ok(), "unexpected error: {:?}", res);

    // Relayed listening on any address.
    let err = peer.start_relayed_listening(relay_id, None).await.unwrap_err();
    assert!(
        matches!(err, ListenRelayErr::ProtocolNotSupported),
        "unexpected error: {}",
        err
    );

    // Listening on a relayed address directly should fail.
    let err = peer.start_listening(relayed_address.clone()).await.unwrap_err();
    assert!(
        matches!(err, ListenErr::Transport(TransportErr::MultiaddrNotSupported(ref addr)) if addr == &relayed_address),
        "unexpected error: {}",
        err
    );

    // Check that the config methods return errors.
    assert!(peer.add_dialing_relay(relay_id, None).await.is_err());
    assert!(peer.set_relay_fallback(PeerId::random(), true).await.is_err());
    assert!(peer.use_specific_relay(PeerId::random(), relay_id, true).await.is_err());
}

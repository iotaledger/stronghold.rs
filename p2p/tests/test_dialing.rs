// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "relay")]

use core::fmt;
use futures::{
    channel::mpsc::{self, Receiver},
    future, StreamExt,
};
#[cfg(not(feature = "tcp-transport"))]
use libp2p::tcp::TokioTcpConfig;
use p2p::{
    assemble_relayed_addr, firewall::FirewallConfiguration, Multiaddr, NetworkEvent, PeerId, StrongholdP2p,
    StrongholdP2pBuilder,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::runtime::Builder;

type TestPeer = StrongholdP2p<Request, Response>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Request;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Response;

async fn init_peer() -> (mpsc::Receiver<NetworkEvent>, TestPeer) {
    let (dummy_fw_tx, _) = mpsc::channel(10);
    let (dummy_rq_tx, _) = mpsc::channel(10);
    let (event_tx, event_rx) = mpsc::channel(10);
    let builder = StrongholdP2pBuilder::new(dummy_fw_tx, dummy_rq_tx, Some(event_tx))
        .with_firewall_config(FirewallConfiguration::allow_all())
        .with_connection_timeout(Duration::from_millis(1));
    #[cfg(not(feature = "tcp-transport"))]
    let peer = {
        let executor = |fut| {
            tokio::spawn(fut);
        };
        builder.build_with_transport(TokioTcpConfig::new(), executor).await
    };
    #[cfg(feature = "tcp-transport")]
    let peer = builder.build().await.unwrap();
    (event_rx, peer)
}

fn rand_bool(n: u8) -> bool {
    rand::random::<u8>() % n > 0
}

#[derive(Debug)]
struct TestTargetConfig {
    listening_plain: bool,
    listening_relay: bool,
}

impl TestTargetConfig {
    fn random() -> Self {
        TestTargetConfig {
            listening_plain: rand_bool(5),
            listening_relay: rand_bool(5),
        }
    }
}

#[derive(Debug)]
enum UseRelay {
    Default,
    NoRelay,
    UseSpecificRelay,
}

#[derive(Debug)]
struct TestSourceConfig {
    knows_direct_target_addr: bool,
    knows_relayed_target_addr: bool,
    knows_relay: bool,
    knows_relay_addr: bool,
    set_relay: UseRelay,
}

impl TestSourceConfig {
    fn random() -> Self {
        let set_relay = match rand::random::<u8>() % 10 {
            0 | 1 | 2 | 3 => UseRelay::Default,
            4 | 5 | 6 => UseRelay::UseSpecificRelay,
            7 | 8 | 9 => UseRelay::NoRelay,
            _ => unreachable!(),
        };
        let knows_direct_target_addr = cfg!(feature = "mdns").then(|| true).unwrap_or_else(|| rand_bool(5));
        let knows_relayed_target_addr = cfg!(feature = "mdns").then(|| true).unwrap_or_else(|| rand_bool(5));
        let knows_relay_addr = cfg!(feature = "mdns").then(|| true).unwrap_or_else(|| rand_bool(5));
        TestSourceConfig {
            knows_direct_target_addr,
            knows_relayed_target_addr,
            knows_relay: true,
            knows_relay_addr,
            set_relay,
        }
    }
}

struct TestConfig {
    source_config: TestSourceConfig,
    source_peer: TestPeer,
    source_event_rx: mpsc::Receiver<NetworkEvent>,
    source_id: PeerId,

    relay_id: PeerId,
    relay_addr: Multiaddr,

    target_config: TestTargetConfig,
    target_peer: TestPeer,
    target_event_rx: mpsc::Receiver<NetworkEvent>,
    target_id: PeerId,
    target_addr: Option<Multiaddr>,
    target_relayed_addr: Option<Multiaddr>,
}

impl fmt::Display for TestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n\nCONFIG\n[Relay]: {:?}\n[Source Peer]: {:?}
            [Test Config]: {:?}\n[Target Peer]: {:?}
            [Test Config]: {:?}\n\n",
            self.relay_id, self.source_id, self.source_config, self.target_id, self.target_config
        )
    }
}
impl TestConfig {
    async fn new(relay_id: PeerId, relay_addr: Multiaddr) -> Self {
        let (source_event_rx, source_peer) = init_peer().await;
        let source_id = source_peer.get_peer_id();
        let (target_event_rx, target_peer) = init_peer().await;
        let target_id = target_peer.get_peer_id();
        TestConfig {
            source_config: TestSourceConfig::random(),
            source_peer,
            source_event_rx,
            source_id,
            relay_id,
            relay_addr,
            target_config: TestTargetConfig::random(),
            target_peer,
            target_event_rx,
            target_id,
            target_addr: None,
            target_relayed_addr: None,
        }
    }

    async fn configure_peer(&mut self) {
        if self.target_config.listening_plain {
            let target_addr = self
                .target_peer
                .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .await
                .unwrap();

            let mut target_listeners = self.target_peer.get_listeners().await;
            assert_eq!(target_listeners.len(), 1);
            let target_listener = target_listeners.pop().unwrap();
            assert!(target_listener.uses_relay.is_none());
            assert!(target_listener.addrs.into_iter().any(|a| a == target_addr));

            self.target_addr = Some(target_addr);
        }
        if self.target_config.listening_relay {
            let relayed_addr = self
                .target_peer
                .start_relayed_listening(self.relay_id, Some(self.relay_addr.clone()))
                .await
                .unwrap();

            let target_listeners = self.target_peer.get_listeners().await;
            let mut expected_len = 1;
            self.target_config.listening_plain.then(|| expected_len = 2);
            assert_eq!(target_listeners.len(), expected_len);
            let target_relayed_listener = target_listeners
                .into_iter()
                .find(|l| l.uses_relay == Some(self.relay_id))
                .unwrap();
            assert!(target_relayed_listener.addrs.into_iter().any(|a| a == relayed_addr));

            self.target_relayed_addr = Some(relayed_addr)
        }
        if self.source_config.knows_direct_target_addr {
            let addr = self
                .target_addr
                .clone()
                .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/12345".parse().expect("Invalid Multiaddress."));
            self.source_peer.add_address(self.target_id, addr).await;
        }
        if self.source_config.knows_relayed_target_addr {
            let relayed_addr = assemble_relayed_addr(self.target_id, self.relay_id, self.relay_addr.clone());
            self.source_peer.add_address(self.target_id, relayed_addr).await;
        }

        if self.source_config.knows_relay_addr {
            self.source_peer
                .add_address(self.relay_id, self.relay_addr.clone())
                .await;
        }
        if self.source_config.knows_relay {
            let addr = self.source_peer.add_dialing_relay(self.relay_id, None).await;
            assert_eq!(addr.is_some(), self.source_config.knows_relay_addr);
        }

        match self.source_config.set_relay {
            UseRelay::Default => {}
            UseRelay::NoRelay => self.source_peer.set_relay_fallback(self.target_id, false).await,
            UseRelay::UseSpecificRelay => {
                let addr = self
                    .source_peer
                    .use_specific_relay(self.target_id, self.relay_id, true)
                    .await;
                if self.source_config.knows_relay_addr && self.source_config.knows_relay {
                    assert_eq!(
                        addr.unwrap(),
                        assemble_relayed_addr(self.target_id, self.relay_id, self.relay_addr.clone())
                    );
                } else {
                    assert!(addr.is_none());
                }
            }
        }
    }

    async fn test_dial(&mut self) {
        let config_str = format!("{}", self);

        let res = self.source_peer.connect_peer(self.target_id).await;

        if self.target_config.listening_relay {
            Self::expect_connection(&mut self.target_event_rx, self.relay_id, &config_str).await;
        }

        match self.source_config.set_relay {
            UseRelay::NoRelay => {
                if self.try_direct(&config_str).await {
                    assert!(res.is_ok());
                    return;
                }
                if self.source_config.knows_relayed_target_addr && self.expect_relayed(false, &config_str).await {
                    assert!(res.is_ok());
                    return;
                }
            }
            UseRelay::Default => {
                if self.try_direct(&config_str).await {
                    assert!(res.is_ok());
                    return;
                }
                if (self.source_config.knows_relayed_target_addr
                    || self.source_config.knows_relay && self.source_config.knows_relay_addr)
                    && self.expect_relayed(false, &config_str).await
                {
                    assert!(res.is_ok());
                    return;
                }
            }
            UseRelay::UseSpecificRelay => {
                let knows_relay = self.source_config.knows_relay && self.source_config.knows_relay_addr;
                if knows_relay && self.expect_relayed(false, &config_str).await {
                    assert!(res.is_ok());
                    return;
                }
                if self.try_direct(&config_str).await {
                    assert!(res.is_ok());
                    return;
                }
                if self.source_config.knows_relayed_target_addr && self.expect_relayed(knows_relay, &config_str).await {
                    assert!(res.is_ok());
                    return;
                }
            }
        }
        // if mdns is enabled, there is a chance that the source received the target address via the mdns service
        if !cfg!(feature = "mdns") {
            assert!(res.is_err(), "Unexpected Event {:?} on config {}", res, config_str);
        }
    }

    async fn try_direct(&mut self, config_str: &str) -> bool {
        if self.source_config.knows_direct_target_addr && self.target_config.listening_plain {
            Self::expect_connection(&mut self.source_event_rx, self.target_id, &config_str).await;
            Self::expect_connection(&mut self.target_event_rx, self.source_id, &config_str).await;
            return true;
        }
        false
    }

    async fn expect_relayed(&mut self, is_connected: bool, config_str: &str) -> bool {
        if !is_connected {
            Self::expect_connection(&mut self.source_event_rx, self.relay_id, &config_str).await;
        }
        if self.target_config.listening_relay {
            Self::expect_connection(&mut self.source_event_rx, self.target_id, &config_str).await;
            Self::expect_connection(&mut self.target_event_rx, self.source_id, &config_str).await;
            return true;
        }
        false
    }

    async fn expect_connection(event_rx: &mut Receiver<NetworkEvent>, target: PeerId, config_str: &str) {
        let mut filtered = event_rx.filter(|ev| {
            future::ready(!matches!(
                ev,
                NetworkEvent::NewListenAddr(..)
                    | NetworkEvent::ConnectionClosed { .. }
                    | NetworkEvent::ListenerClosed { .. }
            ))
        });
        let event = filtered.next().await.unwrap();
        assert!(
            matches!(event,  NetworkEvent::ConnectionEstablished { peer, .. } if peer == target),
            "Unexpected Event {:?} on config {}",
            event,
            config_str
        );
    }
}

#[test]
fn test_dialing() {
    let task = async {
        let (_, mut relay_peer) = init_peer().await;
        let relay_id = relay_peer.get_peer_id();
        let relay_addr = relay_peer
            .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .await
            .unwrap();
        let mut relay_listeners = relay_peer.get_listeners().await;
        assert_eq!(relay_listeners.len(), 1);
        let relay_listener = relay_listeners.pop().unwrap();
        assert!(relay_listener.uses_relay.is_none());
        assert!(relay_listener.addrs.into_iter().any(|a| a == relay_addr));

        for _ in 0..100 {
            let mut test = TestConfig::new(relay_id, relay_addr.clone()).await;
            test.configure_peer().await;
            test.test_dial().await;
        }
    };
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(task);
}

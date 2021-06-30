// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::task;
use communication_refactored::{
    assemble_relayed_addr,
    firewall::{FirewallConfiguration, PermissionValue, RequestPermissions, VariantPermission},
    Multiaddr, NetworkEvent, PeerId, ShCommunication, ShCommunicationBuilder,
};
use core::fmt;
use futures::{
    channel::mpsc::{self, Receiver},
    future, StreamExt,
};
#[cfg(not(feature = "tcp-transport"))]
use libp2p_tcp::TcpConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;

type TestComms = ShCommunication<Request, Response, Request>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
struct Request;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
struct Response;

fn init_comms() -> (mpsc::Receiver<NetworkEvent>, TestComms) {
    let (dummy_fw_tx, _) = mpsc::channel(1);
    let (dummy_rq_tx, _) = mpsc::channel(1);
    let (event_tx, event_rx) = mpsc::channel(1);
    let builder = ShCommunicationBuilder::new(dummy_fw_tx, dummy_rq_tx, Some(event_tx))
        .with_firewall_config(FirewallConfiguration::allow_all())
        .with_connection_timeout(Duration::from_millis(1));
    #[cfg(not(feature = "tcp-transport"))]
    let comms = task::block_on(builder.build_with_transport(TcpConfig::new()));
    #[cfg(feature = "tcp-transport")]
    let comms = task::block_on(builder.build());
    (event_rx, comms)
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
    source_comms: TestComms,
    source_event_rx: mpsc::Receiver<NetworkEvent>,
    source_id: PeerId,

    relay_id: PeerId,
    relay_addr: Multiaddr,

    target_config: TestTargetConfig,
    target_comms: TestComms,
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
    fn new(relay_id: PeerId, relay_addr: Multiaddr) -> Self {
        let (source_event_rx, source_comms) = init_comms();
        let source_id = source_comms.get_peer_id();
        let (target_event_rx, target_comms) = init_comms();
        let target_id = target_comms.get_peer_id();
        TestConfig {
            source_config: TestSourceConfig::random(),
            source_comms,
            source_event_rx,
            source_id,
            relay_id,
            relay_addr,
            target_config: TestTargetConfig::random(),
            target_comms,
            target_event_rx,
            target_id,
            target_addr: None,
            target_relayed_addr: None,
        }
    }

    fn configure_comms(&mut self) {
        if self.target_config.listening_plain {
            let target_addr = task::block_on(self.target_comms.start_listening(None)).unwrap();
            self.target_addr = Some(target_addr);
        }
        if self.target_config.listening_relay {
            let relayed_addr = task::block_on(
                self.target_comms
                    .start_relayed_listening(self.relay_id, Some(self.relay_addr.clone())),
            )
            .unwrap();
            self.target_relayed_addr = Some(relayed_addr)
        }
        if self.source_config.knows_direct_target_addr {
            let addr = self
                .target_addr
                .clone()
                .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/12345".parse().expect("Invalid Multiaddress."));
            self.source_comms.add_address(self.target_id, addr);
        }
        if self.source_config.knows_relayed_target_addr {
            let relayed_addr = assemble_relayed_addr(self.target_id, self.relay_id, self.relay_addr.clone());
            self.source_comms.add_address(self.target_id, relayed_addr);
        }

        if self.source_config.knows_relay_addr {
            self.source_comms.add_address(self.relay_id, self.relay_addr.clone());
        }
        if self.source_config.knows_relay {
            let addr = self.source_comms.add_dialing_relay(self.relay_id, None);
            assert_eq!(addr.is_some(), self.source_config.knows_relay_addr);
        }

        match self.source_config.set_relay {
            UseRelay::Default => {}
            UseRelay::NoRelay => self.source_comms.set_relay_fallback(self.target_id, false),
            UseRelay::UseSpecificRelay => {
                let addr = self
                    .source_comms
                    .use_specific_relay(self.target_id, self.relay_id, true);
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

    fn test_dial(&mut self) {
        let config_str = format!("{}", self);

        let res = task::block_on(self.source_comms.dial_peer(&self.target_id));

        if self.target_config.listening_relay {
            Self::expect_connection(&mut self.target_event_rx, self.relay_id, &config_str);
        }

        match self.source_config.set_relay {
            UseRelay::NoRelay => {
                if self.try_direct(&config_str) {
                    assert!(res.is_ok());
                    return;
                }
                if self.source_config.knows_relayed_target_addr && self.expect_relayed(false, &config_str) {
                    assert!(res.is_ok());
                    return;
                }
            }
            UseRelay::Default => {
                if self.try_direct(&config_str) {
                    assert!(res.is_ok());
                    return;
                }
                if (self.source_config.knows_relayed_target_addr
                    || self.source_config.knows_relay && self.source_config.knows_relay_addr)
                    && self.expect_relayed(false, &config_str)
                {
                    assert!(res.is_ok());
                    return;
                }
            }
            UseRelay::UseSpecificRelay => {
                let knows_relay = self.source_config.knows_relay && self.source_config.knows_relay_addr;
                if knows_relay && self.expect_relayed(false, &config_str) {
                    assert!(res.is_ok());
                    return;
                }
                if self.try_direct(&config_str) {
                    assert!(res.is_ok());
                    return;
                }
                if self.source_config.knows_relayed_target_addr && self.expect_relayed(knows_relay, &config_str) {
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

    fn try_direct(&mut self, config_str: &str) -> bool {
        if self.source_config.knows_direct_target_addr && self.target_config.listening_plain {
            Self::expect_connection(&mut self.source_event_rx, self.target_id, &config_str);
            Self::expect_connection(&mut self.target_event_rx, self.source_id, &config_str);
            return true;
        }
        false
    }

    fn expect_relayed(&mut self, is_connected: bool, config_str: &str) -> bool {
        if !is_connected {
            Self::expect_connection(&mut self.source_event_rx, self.relay_id, &config_str);
        }
        if self.target_config.listening_relay {
            Self::expect_connection(&mut self.source_event_rx, self.target_id, &config_str);
            Self::expect_connection(&mut self.target_event_rx, self.source_id, &config_str);
            return true;
        }
        false
    }

    fn expect_connection(event_rx: &mut Receiver<NetworkEvent>, target: PeerId, config_str: &str) {
        let mut filtered = event_rx.filter(|ev| {
            future::ready(!matches!(
                ev,
                NetworkEvent::NewListenAddr(..) | NetworkEvent::ConnectionClosed { .. }
            ))
        });
        let event = task::block_on(filtered.next()).unwrap();
        assert!(
            matches!(event,  NetworkEvent::ConnectionEstablished { peer, .. } if peer == target),
            "Unexpected Event {:?} on config {}",
            event,
            config_str
        );
    }

    fn shutdown(self) {
        task::block_on(async {
            self.source_comms.shutdown();
            self.target_comms.shutdown();
        })
    }
}

#[test]
fn test_dialing() {
    let (_, relay_comms) = init_comms();
    let relay_id = relay_comms.get_peer_id();
    let relay_addr = task::block_on(relay_comms.start_listening(None)).unwrap();

    for _ in 0..100 {
        let mut test = TestConfig::new(relay_id, relay_addr.clone());
        test.configure_comms();
        test.test_dial();
        test.shutdown()
    }
}

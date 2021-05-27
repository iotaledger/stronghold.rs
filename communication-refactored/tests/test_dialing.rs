// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication_refactored::{
    assemble_relayed_addr,
    firewall::{PermissionValue, RequestPermissions, Rule, RuleDirection, ToPermissionVariants, VariantPermission},
    NetBehaviour, NetBehaviourConfig,
};
use core::fmt;
use futures::{channel::mpsc, executor::LocalPool, task::SpawnExt, FutureExt};
use libp2p::{
    core::{connection::ListenerId, identity, transport::Transport, upgrade, ConnectedPoint, PeerId},
    mdns::{Mdns, MdnsConfig},
    multiaddr::Protocol,
    noise::{Keypair, NoiseConfig, X25519Spec},
    relay::{new_transport_and_behaviour, RelayConfig},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp::TcpConfig,
    yamux::YamuxConfig,
    Multiaddr,
};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

type TestSwarm = Swarm<NetBehaviour<Request, Response, RequestPermission>>;

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

fn init_swarm(pool: &mut LocalPool) -> (PeerId, TestSwarm) {
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

    let mut cfg = NetBehaviourConfig::default();
    cfg.firewall.set_default(Rule::allow_all(), RuleDirection::Both);
    cfg.connection_timeout = Duration::from_millis(500);
    let mdns = pool
        .run_until(Mdns::new(MdnsConfig::default()))
        .expect("Failed to create mdns behaviour.");
    let (firewall_dummy_sender, _) = mpsc::channel(1);
    let behaviour = NetBehaviour::new(cfg, mdns, relay_behaviour, firewall_dummy_sender);
    let swarm = Swarm::new(transport, behaviour, peer);
    (peer, swarm)
}

fn start_listening(pool: &mut LocalPool, swarm: &mut TestSwarm) -> (ListenerId, Multiaddr) {
    let addr = "/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress.");
    let listener = swarm.listen_on(addr).unwrap();
    match pool.run_until(swarm.next_event()) {
        SwarmEvent::NewListenAddr(addr) => (listener, addr),
        other => panic!("Unexepected event: {:?}", other),
    }
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
    UseActualRelay,
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
            4 | 5 | 6 => UseRelay::UseActualRelay,
            7 | 8 | 9 => UseRelay::NoRelay,
            _ => unreachable!(),
        };
        TestSourceConfig {
            knows_direct_target_addr: rand_bool(5),
            knows_relayed_target_addr: rand_bool(5),
            knows_relay: true,
            knows_relay_addr: rand_bool(5),
            set_relay,
        }
    }
}

struct TestConfig {
    source_config: TestSourceConfig,
    source_swarm: TestSwarm,
    source_id: PeerId,

    relay_id: PeerId,
    relay_addr: Multiaddr,

    target_config: TestTargetConfig,
    target_swarm: TestSwarm,
    target_id: PeerId,
    target_addr: Option<Multiaddr>,

    target_direct_listener: Option<ListenerId>,
    target_relayed_listener: Option<ListenerId>,
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
    fn new(pool: &mut LocalPool, relay_id: PeerId, relay_addr: Multiaddr) -> Self {
        let (source_id, source_swarm) = init_swarm(pool);
        let (target_id, target_swarm) = init_swarm(pool);
        TestConfig {
            source_config: TestSourceConfig::random(),
            source_swarm,
            source_id,
            relay_id,
            relay_addr,
            target_config: TestTargetConfig::random(),
            target_swarm,
            target_id,
            target_addr: None,
            target_direct_listener: None,
            target_relayed_listener: None,
        }
    }

    fn start_relay_listening(&mut self, pool: &mut LocalPool) -> (ListenerId, Multiaddr) {
        let relayed_addr = assemble_relayed_addr(self.target_id, self.relay_id, self.relay_addr.clone());
        let listener = self.target_swarm.listen_on(relayed_addr.clone()).unwrap();
        pool.run_until(async {
            loop {
                match self.target_swarm.next_event().await {
                    SwarmEvent::NewListenAddr(addr) => {
                        if addr == relayed_addr {
                            return (listener, addr);
                        } else if !self.target_config.listening_plain {
                            panic!("addr: {:?}", addr);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } | SwarmEvent::Dialing(peer_id) => {
                        assert_eq!(peer_id, self.relay_id)
                    }
                    other => panic!("Unexepected event: {:?},{}", other, self),
                }
            }
        })
    }

    fn configure_swarms(&mut self, pool: &mut LocalPool) {
        if self.target_config.listening_plain {
            let (listener, target_addr) = start_listening(pool, &mut self.target_swarm);
            self.target_addr = Some(target_addr);
            self.target_direct_listener = Some(listener);
        }
        if self.target_config.listening_relay {
            let (listener, _) = self.start_relay_listening(pool);
            self.target_relayed_listener = Some(listener)
        }
        if self.source_config.knows_direct_target_addr {
            self.source_swarm.behaviour_mut().add_address(
                self.target_id,
                self.target_addr
                    .clone()
                    .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/12345".parse().expect("Invalid Multiaddress.")),
            )
        }
        if self.source_config.knows_relayed_target_addr {
            let relayed_addr = assemble_relayed_addr(self.target_id, self.relay_id, self.relay_addr.clone());
            self.source_swarm
                .behaviour_mut()
                .add_address(self.target_id, relayed_addr);
        }

        if self.source_config.knows_relay_addr {
            self.source_swarm
                .behaviour_mut()
                .add_address(self.relay_id, self.relay_addr.clone());
        }
        if self.source_config.knows_relay {
            let addr = self.source_swarm.behaviour_mut().add_dialing_relay(self.relay_id, None);
            assert_eq!(addr.is_some(), self.source_config.knows_relay_addr);
        }

        match self.source_config.set_relay {
            UseRelay::Default => {}
            UseRelay::NoRelay => self.source_swarm.behaviour_mut().set_not_use_relay(self.target_id),
            UseRelay::UseActualRelay => {
                let addr = self
                    .source_swarm
                    .behaviour_mut()
                    .set_use_relay(self.target_id, self.relay_id);
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

    fn test_dial(self, pool: &mut LocalPool) {
        let config_str = format!("{}", self);
        let TestConfig {
            mut source_swarm,
            source_config,
            target_id,
            target_config,
            mut target_swarm,
            relay_id,
            ..
        } = self;

        pool.spawner()
            .spawn(async move {
                loop {
                    target_swarm.next().await;
                }
            })
            .unwrap();

        let knows_direct = source_config.knows_direct_target_addr || source_config.knows_relayed_target_addr;
        let expect_knows_addrs = {
            match source_config.set_relay {
                UseRelay::NoRelay => knows_direct,
                UseRelay::UseActualRelay => source_config.knows_relay && source_config.knows_relay_addr,
                UseRelay::Default => knows_direct || source_config.knows_relay && source_config.knows_relay_addr,
            }
        };
        let knows_addr = source_swarm.dial(&target_id).is_ok();

        assert_eq!(knows_addr, expect_knows_addrs);
        if !knows_addr {
            return;
        }

        pool.run_until(async {
            let allows_direct = matches!(source_config.set_relay, UseRelay::Default | UseRelay::NoRelay);
            let allows_relay = matches!(source_config.set_relay, UseRelay::Default | UseRelay::UseActualRelay);

            if allows_direct && source_config.knows_direct_target_addr {
                // match source_swarm.next_event().await {
                //     SwarmEvent::Dialing(peer) if peer == target_id => {}
                //     other => panic!("Unexepected event: {:?}", other)
                // }
                if target_config.listening_plain {
                    match source_swarm.next_event().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_id => return,
                        other => panic!("Unexepected event: {:?},{}", other, config_str),
                    }
                } else {
                    match source_swarm.next_event().await {
                        SwarmEvent::UnreachableAddr { peer_id, .. } if peer_id == target_id => {}
                        other => panic!("Unexepected event: {:?},{}", other, config_str),
                    }
                }
            }
            if allows_direct && source_config.knows_relayed_target_addr
                || allows_relay && source_config.knows_relay && source_config.knows_relay_addr
            {
                match source_swarm.next_event().await {
                    SwarmEvent::Dialing(peer) if peer == relay_id => {}
                    other => panic!("Unexepected event: {:?},{}", other, config_str),
                }
                match source_swarm.next_event().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_id => {}
                    other => panic!("Unexepected event: {:?},{}", other, config_str),
                }
                if target_config.listening_relay {
                    match source_swarm.next_event().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_id => {}
                        other => panic!("Unexepected event: {:?},{}", other, config_str),
                    }
                } else {
                    match source_swarm.next_event().await {
                        SwarmEvent::UnreachableAddr { peer_id, .. } if peer_id == target_id => {}
                        other => panic!("Unexepected event: {:?},{}", other, config_str),
                    }
                }
            }
        });
    }
}

#[test]
fn test_dialing() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let (relay_id, mut relay_swarm) = init_swarm(&mut pool);
    let (_, relay_addr) = start_listening(&mut pool, &mut relay_swarm);

    spawner
        .spawn(async move {
            loop {
                relay_swarm.next().await;
            }
        })
        .unwrap();

    for _ in 0..50 {
        let mut config = TestConfig::new(&mut pool, relay_id, relay_addr.clone());
        config.configure_swarms(&mut pool);
        config.test_dial(&mut pool);
    }
}

#[test]
fn test_invalid_relay() {
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let (relay_id, mut relay_swarm) = init_swarm(&mut pool);
    let (_, relay_addr) = start_listening(&mut pool, &mut relay_swarm);

    spawner
        .spawn(async move {
            loop {
                relay_swarm.next().await;
            }
        })
        .unwrap();
    let (_, mut source_swarm) = init_swarm(&mut pool);
    let dummy_peer = PeerId::random();
    let dummy_relayed_addr = assemble_relayed_addr(dummy_peer, relay_id, relay_addr);
    source_swarm.behaviour_mut().add_address(dummy_peer, dummy_relayed_addr);
    source_swarm.dial(&dummy_peer).unwrap();
    pool.run_until(async {
        assert!(matches!(source_swarm.next_event().await, SwarmEvent::Dialing(peer_id) if peer_id == relay_id));
        assert!(matches!(source_swarm.next_event().await, SwarmEvent::ConnectionEstablished{peer_id, ..} if peer_id == relay_id));
        assert!(matches!(source_swarm.next_event().await, SwarmEvent::UnreachableAddr{peer_id, ..} if peer_id == dummy_peer));
    });
}

fn dial_peer(
    pool: &mut LocalPool,
    swarm_a: &mut TestSwarm,
    peer_a_id: PeerId,
    swarm_b: &mut TestSwarm,
    peer_b_id: PeerId,
    peer_b_addr: Option<Multiaddr>,
) -> bool {
    if swarm_a.dial(&peer_b_id).is_err() {
        return false;
    }
    pool.run_until(async {
        loop {
            futures::select! {
                event = swarm_a.next_event().fuse() => match event {
                    SwarmEvent::Dialing(peer) => assert_eq!(peer, peer_b_id),
                    SwarmEvent::ConnectionEstablished {peer_id, endpoint: ConnectedPoint::Dialer {address}, num_established} => {
                        assert_eq!(peer_id, peer_b_id);
                        if let Some(peer_b_addr) = peer_b_addr.as_ref() {
                            assert_eq!(address, peer_b_addr.clone().with(Protocol::P2p(peer_b_id.into())));
                        }
                        assert_eq!(num_established, NonZeroU32::new(1).unwrap());
                        return true;
                    },
                    other => panic!("Unexpected SwarmEvent: {:?}", other)
                },
                event = swarm_b.next_event().fuse() => match event {
                    SwarmEvent::IncomingConnection {local_addr, ..}  => {
                        if let Some(peer_b_addr) = peer_b_addr.as_ref() {
                        assert_eq!(&local_addr, peer_b_addr);}
                    }
                    SwarmEvent::ConnectionEstablished {peer_id, endpoint: ConnectedPoint::Listener {local_addr, send_back_addr}, num_established} => {
                        assert_eq!(peer_id, peer_a_id);
                        if let Some(peer_b_addr) = peer_b_addr.as_ref() {
                        assert_eq!(&local_addr, peer_b_addr);}
                        assert_eq!(num_established, NonZeroU32::new(1).unwrap());
                        assert!(swarm_b
                            .behaviour_mut()
                            .addresses_of_peer(&peer_a_id)
                            .contains(&send_back_addr));
                    }
                    SwarmEvent::NewListenAddr(..) => {}
                    other => panic!("Unexpected SwarmEvent: {:?}", other)
                }
            }
        }
    })
}

#[test]
fn test_addresses() {
    let mut pool = LocalPool::new();

    let (peer_a_id, mut swarm_a) = init_swarm(&mut pool);
    let (peer_b_id, mut swarm_b) = init_swarm(&mut pool);
    let (_, peer_b_addr) = start_listening(&mut pool, &mut swarm_b);

    assert!(!swarm_a
        .behaviour_mut()
        .addresses_of_peer(&peer_b_id)
        .contains(&peer_b_addr));
    assert!(!dial_peer(
        &mut pool,
        &mut swarm_a,
        peer_a_id,
        &mut swarm_b,
        peer_b_id,
        Some(peer_b_addr.clone())
    ));

    swarm_a.behaviour_mut().add_address(peer_b_id, peer_b_addr.clone());
    swarm_a.behaviour_mut().remove_address(&peer_b_id, &peer_b_addr);
    assert!(!swarm_a
        .behaviour_mut()
        .addresses_of_peer(&peer_b_id)
        .contains(&peer_b_addr));
    assert!(!dial_peer(
        &mut pool,
        &mut swarm_a,
        peer_a_id,
        &mut swarm_b,
        peer_b_id,
        Some(peer_b_addr.clone())
    ));

    swarm_a.behaviour_mut().add_address(peer_b_id, peer_b_addr.clone());
    assert!(swarm_a
        .behaviour_mut()
        .addresses_of_peer(&peer_b_id)
        .contains(&peer_b_addr));
    assert!(dial_peer(
        &mut pool,
        &mut swarm_a,
        peer_a_id,
        &mut swarm_b,
        peer_b_id,
        Some(peer_b_addr)
    ));
}

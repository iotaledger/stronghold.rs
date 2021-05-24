// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};

struct PeerAddress {
    direct: VecDeque<Multiaddr>,
    use_relay: Option<bool>,
    relay: Option<PeerId>,
    currently_used: HashMap<Multiaddr, u8>,
}

impl Default for PeerAddress {
    fn default() -> Self {
        PeerAddress {
            direct: VecDeque::new(),
            use_relay: None,
            relay: None,
            currently_used: HashMap::new(),
        }
    }
}

pub struct AddressInfo {
    peers: HashMap<PeerId, PeerAddress>,
    relays: SmallVec<[PeerId; 10]>,
}

impl AddressInfo {
    pub fn new() -> Self {
        AddressInfo {
            peers: HashMap::new(),
            relays: SmallVec::new(),
        }
    }

    pub fn get_addrs(&self, target: &PeerId) -> Vec<Multiaddr> {
        self.peers
            .get(target)
            .map(|addrs| {
                let mut peer_addrs = Vec::new();
                if matches!(addrs.use_relay, Some(false)) || matches!(addrs.use_relay, None) {
                    peer_addrs.extend(addrs.direct.clone());
                }
                if matches!(addrs.use_relay, Some(true)) || matches!(addrs.use_relay, None) {
                    let relayed = addrs
                        .relay
                        .and_then(|r| self.get_relay_addr(&r).map(|a| vec![a]))
                        .unwrap_or_else(|| {
                            self.relays
                                .clone()
                                .into_iter()
                                .filter_map(|r| self.get_relay_addr(&r).map(|a| to_relayed(*target, r, a)))
                                .collect()
                        });
                    peer_addrs.extend(relayed);
                }
                peer_addrs
            })
            .unwrap_or_default()
    }

    pub fn add_addrs(&mut self, peer: PeerId, addr: Multiaddr) {
        let addrs = self.peers.entry(peer).or_default();
        if !addrs.direct.contains(&addr) {
            addrs.direct.push_back(addr);
        }
    }

    pub fn remove_address(&mut self, peer: &PeerId, addrs: &Multiaddr) {
        if let Some(PeerAddress { direct, .. }) = self.peers.get_mut(peer) {
            direct.retain(|a| a != addrs);
        }
    }

    pub fn set_no_relay(&mut self, peer: PeerId) {
        let addrs = self.peers.entry(peer).or_default();
        addrs.use_relay = Some(false);
        addrs.relay = None;
    }

    pub fn set_relay(&mut self, target: PeerId, relay: PeerId) -> Option<Multiaddr> {
        let addrs = self.peers.entry(target).or_default();
        addrs.use_relay = Some(true);
        addrs.relay = Some(relay);
        self.get_relay_addr(&relay).map(|a| to_relayed(target, relay, a))
    }

    pub fn on_connection_established(&mut self, peer: PeerId, addr: Multiaddr) {
        let peer_addr = self.peers.entry(peer).or_default();
        let relay = addr.iter().find(|p| p == &Protocol::P2pCircuit).and_then(|_| {
            addr.iter().find_map(|p| match p {
                Protocol::P2p(relay) if relay != peer.into() => PeerId::from_multihash(relay).ok(),
                _ => None,
            })
        });
        peer_addr.use_relay = Some(relay.is_some());
        peer_addr.relay = relay;
        if relay.is_none() && !peer_addr.direct.contains(&addr) {
            peer_addr.direct.push_front(addr.clone())
        }
        let connections = peer_addr.currently_used.entry(addr).or_insert(0);
        *connections += 1;
    }

    pub fn on_connection_closed(&mut self, peer: PeerId, addr: &Multiaddr) {
        self.peers.entry(peer).and_modify(|peer_addrs| {
            if let Some(connections) = peer_addrs.currently_used.remove(addr) {
                if connections > 1 {
                    peer_addrs.currently_used.insert(addr.clone(), connections - 1);
                }
            }
        });
    }

    pub fn get_relay_addr(&self, peer: &PeerId) -> Option<Multiaddr> {
        if !self.relays.contains(peer) {
            return None;
        }
        self.peers.get(peer).and_then(|a| a.direct.front().cloned())
    }

    pub fn add_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        if self.relays.contains(&peer) {
            return self.get_relay_addr(&peer);
        }
        if let Some(addr) = address.as_ref() {
            self.add_addrs(peer, addr.clone());
        }
        self.relays.push(peer);
        address.or_else(|| self.peers.get(&peer).and_then(|addrs| addrs.direct.front().cloned()))
    }

    pub fn remove_relay(&mut self, peer: &PeerId) {
        self.relays.retain(|p| p == peer)
    }
}

fn to_relayed(target: PeerId, relay: PeerId, mut relay_addr: Multiaddr) -> Multiaddr {
    let relay_proto = Multiaddr::empty()
        .with(Protocol::P2p(relay.into()))
        .with(Protocol::P2pCircuit);

    if !relay_addr.ends_with(&relay_proto) {
        relay_proto.into_iter().for_each(|p| relay_addr.push(p));
    }
    relay_addr.push(Protocol::P2p(target.into()));
    relay_addr
}

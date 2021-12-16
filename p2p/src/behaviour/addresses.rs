// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::serde::SerdeAddressInfo;

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};

// Known addresses and relay config of a remote peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddress {
    // Known addresses e.g. that have been explicitly added or already connected.
    known: VecDeque<Multiaddr>,

    // Try relay peer if a target can not be reached directly.
    use_relay_fallback: bool,
}

impl Default for PeerAddress {
    fn default() -> Self {
        PeerAddress {
            known: VecDeque::new(),

            use_relay_fallback: true,
        }
    }
}

// Known relays and peer addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "SerdeAddressInfo")]
#[serde(into = "SerdeAddressInfo")]
pub struct AddressInfo {
    // Addresses and relay config for each peer.
    pub peers: HashMap<PeerId, PeerAddress>,

    // Known relays to use as fallback for dialing.
    pub relays: SmallVec<[PeerId; 10]>,
}

impl AddressInfo {
    // Known addresses of a peer ordered based on likeliness to be reachable.
    // Optionally includes a relayed target address for each known dialing relay.
    pub fn get_addrs(&self, target: &PeerId) -> Vec<Multiaddr> {
        let addrs = self.peers.get(target).cloned().unwrap_or_default();
        #[allow(unused_mut)]
        let mut peer_addrs: Vec<Multiaddr> = addrs.known.into();

        if addrs.use_relay_fallback {
            let relayed = self
                .relays
                .iter()
                .filter_map(|r| self.get_relay_addr(r).map(|a| assemble_relayed_addr(*target, *r, a)));
            peer_addrs.extend(relayed);
        }
        peer_addrs
    }

    // Add address from the list of addresses that are tried when dialing the remote.
    pub fn add_addrs(&mut self, peer: PeerId, addr: Multiaddr) {
        let addrs = self.peers.entry(peer).or_default();
        if !addrs.known.contains(&addr) {
            addrs.known.push_back(addr);
        }
    }

    // Remove address from the list of addresses that are tried when dialing the remote.
    pub fn remove_address(&mut self, peer: &PeerId, addrs: &Multiaddr) {
        if let Some(PeerAddress { known, .. }) = self.peers.get_mut(peer) {
            known.retain(|a| a != addrs);
        }
    }

    // Configure whether to try reaching the target via a relay if no known address can be reached.
    pub fn set_relay_fallback(&mut self, peer: PeerId, use_relay_fallback: bool) {
        let addrs = self.peers.entry(peer).or_default();
        addrs.use_relay_fallback = use_relay_fallback;
    }

    // Add a address for dialing the target via the given relay.
    // Optionally stop using other relays as fallback.
    pub fn use_relay(&mut self, target: PeerId, relay: PeerId, is_exclusive: bool) -> Option<Multiaddr> {
        let relayed_addr = self
            .get_relay_addr(&relay)
            .map(|a| assemble_relayed_addr(target, relay, a))?;
        let addrs = self.peers.entry(target).or_default();
        addrs.known.push_front(relayed_addr.clone());
        if is_exclusive {
            addrs.use_relay_fallback = false;
        }
        Some(relayed_addr)
    }

    // Move address in the list to the front i.g. the first address that will be tried when dialing the target.
    pub fn prioritize_addr(&mut self, peer: PeerId, addr: Multiaddr) {
        let peer_addr = self.peers.entry(peer).or_default();
        if peer_addr.known.front() != Some(&addr) {
            peer_addr.known.retain(|a| a != &addr);
            peer_addr.known.push_front(addr);
        }
    }

    // Move address in the list to the back i.g. the last known address that will be tried when dialing the target.
    pub fn deprioritize_addr(&mut self, peer: PeerId, addr: Multiaddr) {
        let peer_addr = self.peers.entry(peer).or_default();
        if peer_addr.known.back() != Some(&addr) {
            peer_addr.known.retain(|a| a != &addr);
            peer_addr.known.push_back(addr);
        }
    }

    // Get the first address of a relay peer.
    // Return [`None`] if the peer is not a relay, or no address is known.
    pub fn get_relay_addr(&self, peer: &PeerId) -> Option<Multiaddr> {
        if !self.relays.contains(peer) {
            return None;
        }
        self.peers.get(peer).and_then(|a| a.known.front().cloned())
    }

    // Add a peer as relay peer, optionally add a known address for the peer.
    // Return [`None`] if no address for the relay is known yet.
    // **Note**: even if no addresses are known, the peer will be added to the dialing relays.
    pub fn add_relay(&mut self, peer: PeerId, address: Option<Multiaddr>) -> Option<Multiaddr> {
        if self.relays.contains(&peer) {
            return self.get_relay_addr(&peer);
        }
        if let Some(addr) = address.as_ref() {
            self.add_addrs(peer, addr.clone());
        }
        self.relays.push(peer);
        address.or_else(|| self.peers.get(&peer).and_then(|addrs| addrs.known.front().cloned()))
    }

    // Remove a peer from the list of fallback dialing relays.
    // Returns `false` if the peer was not among the known relays.
    //
    // **Note**: Known relayed addresses for remote peers using this relay will not be influenced by this.
    pub fn remove_relay(&mut self, peer: &PeerId) -> bool {
        if self.relays.contains(peer) {
            self.relays.retain(|p| p == peer);
            true
        } else {
            false
        }
    }
}

/// Assemble a relayed address for the target following the syntax
/// `<relay-addr>/p2p/<relay-id>/p2p-circuit/p2p/<target-id>`.
/// The address can be used to reach the target peer if they are listening on that relay.
pub fn assemble_relayed_addr(target: PeerId, relay: PeerId, mut relay_addr: Multiaddr) -> Multiaddr {
    let relay_proto = Multiaddr::empty()
        .with(Protocol::P2p(relay.into()))
        .with(Protocol::P2pCircuit);

    if !relay_addr.ends_with(&relay_proto) {
        relay_proto.into_iter().for_each(|p| relay_addr.push(p));
    }
    relay_addr.push(Protocol::P2p(target.into()));
    relay_addr
}

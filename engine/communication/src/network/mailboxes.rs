// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::error::{QueryError, QueryResult};
#[cfg(test)]
use core::str::FromStr;
use libp2p::core::{Multiaddr, PeerId};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(super) struct Mailboxes {
    mailboxes: BTreeMap<PeerId, Multiaddr>,
    default: PeerId,
}

impl Mailboxes {
    pub fn new(peer_id: PeerId, addr: Multiaddr) -> Self {
        let default = peer_id.clone();
        let mut mailboxes = BTreeMap::new();
        mailboxes.insert(peer_id, addr);
        Mailboxes { mailboxes, default }
    }

    pub fn add_mailbox(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.mailboxes.insert(peer_id, addr);
    }

    pub fn get_mailboxes(&mut self) -> &BTreeMap<PeerId, Multiaddr> {
        &self.mailboxes
    }

    pub fn get_default(&self) -> &PeerId {
        &self.default
    }

    pub fn set_default(&mut self, mailbox_peer: PeerId) -> QueryResult<()> {
        self.find_mailbox(&mailbox_peer)
            .ok_or_else(|| QueryError::Mailbox(format!("No know Mailbox for{}", mailbox_peer)))?;
        self.default = mailbox_peer;
        Ok(())
    }

    pub fn find_mailbox(&self, mailbox_peer: &PeerId) -> Option<(&PeerId, &Multiaddr)> {
        self.mailboxes.get_key_value(mailbox_peer)
    }
}

#[cfg(test)]
fn mock_mailboxes() -> Mailboxes {
    Mailboxes::new(PeerId::random(), Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap())
}

#[test]
fn test_new_mailbox() {
    let peer_id = PeerId::random();
    let peer_addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/16384").unwrap();
    let mailboxes = Mailboxes::new(peer_id.clone(), peer_addr.clone());
    assert_eq!(&peer_id, mailboxes.get_default());
    assert_eq!(mailboxes.find_mailbox(&peer_id), Some((&peer_id, &peer_addr)));
}

#[test]
fn test_add_mailbox() {
    let mut mailboxes = mock_mailboxes();
    let peer_id = PeerId::random();
    let peer_addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/16384").unwrap();
    assert!(mailboxes.find_mailbox(&peer_id).is_none());
    mailboxes.add_mailbox(peer_id.clone(), peer_addr.clone());
    assert_eq!(mailboxes.find_mailbox(&peer_id), Some((&peer_id, &peer_addr)));
}

#[test]
fn test_default_mailbox() {
    let mut mailboxes = mock_mailboxes();
    let peer_id = PeerId::random();
    let peer_addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/16384").unwrap();
    assert!(mailboxes.set_default(peer_id.clone()).is_err());

    mailboxes.add_mailbox(peer_id.clone(), peer_addr);
    assert_ne!(&peer_id, mailboxes.get_default());

    assert!(mailboxes.set_default(peer_id.clone()).is_ok());
    assert_eq!(&peer_id, mailboxes.get_default());
}


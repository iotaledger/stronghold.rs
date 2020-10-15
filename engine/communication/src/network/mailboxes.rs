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

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

#[derive(Debug, Clone)]
pub(crate) struct Mailbox {
    pub peer_id: PeerId,
    pub addr: Multiaddr,
}

impl Mailbox {
    pub fn new(peer_id: PeerId, addr: Multiaddr) -> Self {
        Mailbox { peer_id, addr }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Mailboxes {
    mailboxes: Vec<Mailbox>,
    default: PeerId,
}

impl Mailboxes {
    pub fn new(mailbox: Mailbox) -> Self {
        let default = mailbox.clone().peer_id;
        let mailboxes = vec![mailbox];
        Mailboxes { mailboxes, default }
    }

    pub fn add_mailbox(&mut self, mailbox: Mailbox, is_default: bool) {
        if is_default {
            self.default = mailbox.clone().peer_id;
        }
        self.mailboxes.push(mailbox);
    }

    pub fn get_default(&self) -> PeerId {
        self.default.clone()
    }

    pub fn set_default(&mut self, mailbox_peer: PeerId) -> QueryResult<PeerId> {
        self.find_mailbox(&mailbox_peer)
            .ok_or_else(|| QueryError::Mailbox(format!("No know Mailbox for{}", mailbox_peer)))?;
        self.default = mailbox_peer.clone();
        Ok(mailbox_peer)
    }

    pub fn find_mailbox(&self, mailbox_peer: &PeerId) -> Option<Mailbox> {
        self.mailboxes
            .clone()
            .into_iter()
            .find(|mailbox| mailbox.peer_id == *mailbox_peer)
    }
}

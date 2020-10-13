use crate::error::{P2PError, P2PResult};
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

    #[allow(dead_code)]
    pub fn mailboxes_count(&self) -> usize {
        self.mailboxes.len()
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

    pub fn set_default(&mut self, mailbox_peer: PeerId) -> P2PResult<PeerId> {
        self.find_mailbox(&mailbox_peer)
            .ok_or_else(|| P2PError::Mailbox(format!("No know Mailbox for{}", mailbox_peer)))?;
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

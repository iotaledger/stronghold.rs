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

use crate::mailbox_protocol::{MailboxCodec, MailboxProtocol, MailboxRecord, MailboxRequest};
use crate::mailboxes::{Mailbox, Mailboxes};
use crate::network_behaviour::P2PNetworkBehaviour;
use libp2p::{
    build_development_transport,
    core::Multiaddr,
    identity::Keypair,
    kad::{record::store::MemoryStore, record::Key, Kademlia, Quorum, Record},
    mdns::Mdns,
    request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig},
    swarm::{ExpandedSwarm, IntoProtocolsHandler, NetworkBehaviour, ProtocolsHandler},
    PeerId, Swarm,
};
use std::{
    error::Error,
    iter,
    string::String,
    time::{Duration, Instant},
};

mod structs_proto {
    include!(concat!(env!("OUT_DIR"), "/structs.pb.rs"));
}
mod mailbox_protocol;
mod mailboxes;
mod network_behaviour;

type P2PNetworkSwarm = ExpandedSwarm<
    P2PNetworkBehaviour,
    <<<P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <<<P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    <P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler,
    PeerId,
>;

pub struct P2PConfig {
    record_timeout: Duration,
    port: u32,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            record_timeout: Duration::from_secs(9000),
            port: 16384u32,
        }
    }
}

pub struct P2P {
    peer_id: PeerId,
    config: P2PConfig,
    swarm: P2PNetworkSwarm,
    mailboxes: Option<Mailboxes>,
}

impl P2P {
    pub fn new(
        local_keys: Keypair,
        config: P2PConfig,
        mailbox: Option<(PeerId, Multiaddr)>,
    ) -> Result<Self, Box<dyn Error>> {
        let peer_id = PeerId::from(local_keys.public());

        let mut swarm: P2PNetworkSwarm = P2P::create_swarm(local_keys, peer_id.clone())?;

        let addr = format!("/ip4/0.0.0.0/tcp/{}", config.port).parse()?;
        Swarm::listen_on(&mut swarm, addr)?;

        let mailboxes = mailbox.and_then(|(mailbox_id, mailbox_addr)| {
            Swarm::dial_addr(&mut swarm, mailbox_addr.clone())
                .ok()
                .and_then(|()| {
                    swarm.kademlia.add_address(&mailbox_id, mailbox_addr.clone());
                    swarm.kademlia.bootstrap().ok()
                })
                .map(|_| Mailboxes::new(Mailbox::new(mailbox_id, mailbox_addr)))
        });

        Ok(P2P {
            peer_id,
            config,
            mailboxes,
            swarm,
        })
    }

    fn create_swarm(local_keys: Keypair, peer_id: PeerId) -> Result<P2PNetworkSwarm, Box<dyn Error>> {
        let transport = build_development_transport(local_keys)?;
        let kademlia = {
            let store = MemoryStore::new(peer_id.clone());
            Kademlia::new(peer_id.clone(), store)
        };
        let mdns = Mdns::new()?;

        // Create RequestResponse behaviour with MailboxProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MailboxProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MailboxCodec(), protocols, cfg)
        };

        let behaviour = P2PNetworkBehaviour {
            kademlia,
            mdns,
            msg_proto,
        };
        Ok(Swarm::new(transport, behaviour, peer_id))
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub fn add_mailbox(&mut self, mailbox_peer: PeerId, mailbox_addr: Multiaddr, is_default: bool) {
        if Swarm::dial_addr(&mut self.swarm, mailbox_addr.clone()).is_ok() {
            let mailbox = Mailbox::new(mailbox_peer, mailbox_addr);
            if let Some(mailboxes) = self.mailboxes.as_mut() {
                mailboxes.add_mailbox(mailbox, is_default);
            } else {
                self.mailboxes = Some(Mailboxes::new(mailbox));
            }
        } else {
            eprintln!("Can not dial this address");
        }
    }

    pub fn set_default_mailbox(&mut self, mailbox_peer: PeerId) {
        if let Some(mailboxes) = self.mailboxes.as_mut() {
            mailboxes.set_default(mailbox_peer);
        } else {
            eprintln!("No mailboxes.");
        }
    }

    pub fn get_record(&mut self, key_str: String) {
        let key = Key::new(&key_str);
        self.swarm.kademlia.get_record(&key, Quorum::One);
    }

    pub fn put_record_local(&mut self, key_str: String, value_str: String, timeout_sec: Option<Duration>) {
        let duration = timeout_sec.unwrap_or(self.config.record_timeout);
        let record = Record {
            key: Key::new(&key_str),
            value: value_str.into_bytes(),
            publisher: None,
            expires: Some(Instant::now() + duration),
        };
        let put_record = self.swarm.kademlia.put_record(record, Quorum::One);
        if put_record.is_ok() {
            println!("Successfully stored record.");
        } else {
            println!("Error storing record: {:?}", put_record.err());
        }
    }

    pub fn put_record_mailbox(
        &mut self,
        key: String,
        value: String,
        timeout_sec: Option<u64>,
        mailbox_peer_id: Option<PeerId>,
    ) {
        if let Some(mailboxes) = self.mailboxes.clone() {
            if mailbox_peer_id
                .clone()
                .and_then(|peer_id| mailboxes.find_mailbox(&peer_id))
                .is_none()
            {
                eprintln!("No mailbox with this peer id exists.");
                return;
            }
            let record = MailboxRecord {
                key,
                value,
                timeout_sec: timeout_sec.unwrap_or_else(|| self.config.record_timeout.as_secs()),
            };
            let peer = mailbox_peer_id.unwrap_or_else(|| mailboxes.get_default());
            self.swarm
                .msg_proto
                .send_request(&peer, MailboxRequest::Publish(record));
        } else {
            eprintln!("Please add a mailbox first");
        }
    }
}

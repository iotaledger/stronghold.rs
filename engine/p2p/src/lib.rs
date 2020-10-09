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

use crate::error::{P2PError, P2PResult};
use crate::mailbox_protocol::{MailboxCodec, MailboxProtocol, MailboxRequest};
#[cfg(feature="kademlia")]
use crate::mailbox_protocol::MailboxRecord;
#[cfg(feature="kademlia")]
use crate::mailboxes::{Mailbox, Mailboxes};
use crate::network_behaviour::P2PNetworkBehaviour;
use core::{iter, time::Duration};
use libp2p::{
    build_development_transport,
    core::Multiaddr,
    identity::Keypair,
    mdns::Mdns,
    request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig},
    swarm::{ExpandedSwarm, IntoProtocolsHandler, NetworkBehaviour, ProtocolsHandler},
    PeerId, Swarm,
};

#[cfg(feature="kademlia")]
use libp2p::request_response::RequestId;

#[cfg(feature="kademlia")]
use libp2p::kad::{record::store::MemoryStore, record::Key, Kademlia, QueryId, Quorum, Record};
#[cfg(feature="kademlia")]
// TODO: support no_std
use std::time::Instant;

mod structs_proto {
    include!(concat!(env!("OUT_DIR"), "/structs.pb.rs"));
}
mod error;
mod mailbox_protocol;
#[cfg(feature="kademlia")]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    config: P2PConfig,
    swarm: P2PNetworkSwarm,
    #[cfg(feature="kademlia")]
    mailboxes: Option<Mailboxes>,
}

impl P2P {
    pub fn new(local_keys: Keypair, config: P2PConfig, _mailbox: Option<(PeerId, Multiaddr)>) -> P2PResult<Self> {
        let peer_id = PeerId::from(local_keys.public());

        let mut swarm: P2PNetworkSwarm = P2P::create_swarm(local_keys, peer_id.clone())?;

        let addr = format!("/ip4/0.0.0.0/tcp/{}", config.port)
            .parse()
            .map_err(|e| P2PError::ConnectionError(format!("Invalid Port {}: {}", config.port, e)))?;
        Swarm::listen_on(&mut swarm, addr).map_err(|e| P2PError::ConnectionError(format!("{}", e)))?;

        #[cfg(feature="kademlia")]
        let mailboxes = _mailbox.and_then(|(mailbox_id, mailbox_addr)| {
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
            #[cfg(feature="kademlia")]
            mailboxes,
            swarm,
        })
    }

    fn create_swarm(local_keys: Keypair, peer_id: PeerId) -> P2PResult<P2PNetworkSwarm> {
        let transport = build_development_transport(local_keys)
            .map_err(|_| P2PError::ConnectionError("Could not build transport layer".to_string()))?;
        #[cfg(feature="kademlia")]
        let kademlia = {
            let store = MemoryStore::new(peer_id.clone());
            Kademlia::new(peer_id.clone(), store)
        };
        let mdns = Mdns::new().map_err(|_| P2PError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        // Create RequestResponse behaviour with MailboxProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MailboxProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MailboxCodec(), protocols, cfg)
        };

        let behaviour = P2PNetworkBehaviour {
            #[cfg(feature="kademlia")]
            kademlia,
            mdns,
            msg_proto,
        };
        Ok(Swarm::new(transport, behaviour, peer_id))
    }

    pub fn get_local_peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub fn dial_remote(&mut self, peer_addr: Multiaddr) -> P2PResult<()> {
        Swarm::dial_addr(&mut self.swarm, peer_addr.clone())
            .map_err(|_| P2PError::ConnectionError(format!("Could not dial addr {}", peer_addr)))
    }

    pub fn print_known_peer(&mut self) {
        #[cfg(feature="kademlia")]
        for bucket in self.swarm.kademlia.kbuckets() {
            for entry in bucket.iter() {
                println!("key: {:?}, values: {:?}", entry.node.key.preimage(), entry.node.value);
            }
        }
        #[cfg(not(feature="kademlia"))]
        for peer_id in self.swarm.mdns.discovered_nodes() {
            println!("{:?}", peer_id);
        }
    }

    pub fn ping(&mut self, peer_id: PeerId) {
        let ping = MailboxRequest::Ping;
        self.swarm.msg_proto.send_request(&peer_id, ping);
    }

    #[cfg(feature="kademlia")]
    pub fn add_mailbox(&mut self, mailbox_peer: PeerId, mailbox_addr: Multiaddr, is_default: bool) -> P2PResult<()> {
        self.dial_remote(mailbox_addr.clone())?;
        let mailbox = Mailbox::new(mailbox_peer, mailbox_addr);
        if let Some(mailboxes) = self.mailboxes.as_mut() {
            mailboxes.add_mailbox(mailbox, is_default);
        } else {
            self.mailboxes = Some(Mailboxes::new(mailbox));
        }
        Ok(())
    }

    #[cfg(feature="kademlia")]
    pub fn set_default_mailbox(&mut self, mailbox_peer: PeerId) -> P2PResult<PeerId> {
        let mut mailboxes = self
            .mailboxes
            .clone()
            .ok_or_else(|| P2PError::Mailbox("No known mailboxes".to_string()))?;
        mailboxes.set_default(mailbox_peer)
    }

    #[cfg(feature="kademlia")]
    pub fn get_record(&mut self, key_str: String) {
        let key = Key::new(&key_str);
        self.swarm.kademlia.get_record(&key, Quorum::One);
    }

    #[cfg(feature="kademlia")]
    pub fn put_record_local(
        &mut self,
        key_str: String,
        value_str: String,
        timeout_sec: Option<Duration>,
    ) -> P2PResult<QueryId> {
        let duration = timeout_sec.unwrap_or(self.config.record_timeout);
        let record = Record {
            key: Key::new(&key_str),
            value: value_str.into_bytes(),
            publisher: None,
            expires: Some(Instant::now() + duration),
        };
        self.swarm
            .kademlia
            .put_record(record, Quorum::One)
            .map_err(|_| P2PError::KademliaError("Can not store record".to_string()))
    }

    #[cfg(feature="kademlia")]
    pub fn put_record_mailbox(
        &mut self,
        key: String,
        value: String,
        timeout_sec: Option<u64>,
        mailbox_peer_id: Option<PeerId>,
    ) -> P2PResult<RequestId> {
        let mailboxes = self
            .mailboxes
            .clone()
            .ok_or_else(|| P2PError::Mailbox("No known mailboxes".to_string()))?;
        let peer = if let Some(peer_id) = mailbox_peer_id {
            mailboxes
                .find_mailbox(&peer_id)
                .map(|mailbox| mailbox.peer_id)
                .ok_or_else(|| P2PError::Mailbox(format!("No know mailbox for {}", peer_id)))
        } else {
            Ok(mailboxes.get_default())
        }?;
        let record = MailboxRecord {
            key,
            value,
            timeout_sec: timeout_sec.unwrap_or_else(|| self.config.record_timeout.as_secs()),
        };
        Ok(self
            .swarm
            .msg_proto
            .send_request(&peer, MailboxRequest::Publish(record)))
    }
}

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
#[cfg(feature = "kademlia")]
use crate::behaviour::SwarmContext;
#[cfg(test)]
use crate::message::Response;
#[cfg(feature = "kademlia")]
use crate::message::{MailboxRecord, Request};
use crate::{
    behaviour::{InboundEventCodec, P2PNetworkBehaviour},
    error::{QueryError, QueryResult},
};
use core::str::FromStr;
use libp2p::{
    build_development_transport,
    core::{connection::ListenerId, Multiaddr, PeerId},
    identity::Keypair,
    swarm::{ExpandedSwarm, IntoProtocolsHandler, NetworkBehaviour, ProtocolsHandler, Swarm},
};
#[cfg(test)]
use libp2p::{kad::KademliaEvent, request_response::RequestResponseEvent};
#[cfg(feature = "kademlia")]
use mailboxes::Mailboxes;

#[cfg(feature = "kademlia")]
use libp2p::request_response::RequestId;

#[cfg(feature = "kademlia")]
mod mailboxes;

type P2PNetworkSwarm<C>= ExpandedSwarm<
    P2PNetworkBehaviour<C>,
    <<<P2PNetworkBehaviour<C> as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <<<P2PNetworkBehaviour<C> as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    <P2PNetworkBehaviour<C> as NetworkBehaviour>::ProtocolsHandler,
    PeerId,
>;

pub struct P2PNetwork<C: InboundEventCodec + Send + 'static> {
    peer_id: PeerId,
    /// property to use the P2PNetworkBehaviour
    pub swarm: P2PNetworkSwarm<C>,
    #[cfg(feature = "kademlia")]
    mailboxes: Option<Mailboxes>,
}

impl<C: InboundEventCodec + Send + 'static> P2PNetwork<C> {
    /// Creates a new P2PNetwork that manages the all communication and implements the P2PNetworkBehaviour for the
    /// Swarm. Apart from that, mailboxes can be connected to deposit records there.
    ///
    /// # Example
    /// ```no_run
    /// use communication::{
    ///     behaviour::{InboundEventCodec, P2PNetworkBehaviour, SwarmContext},
    ///     error::QueryResult,
    ///     message::{Request, Response},
    ///     network::P2PNetwork,
    /// };
    /// use libp2p::{
    ///     core::{identity::Keypair, Multiaddr, PeerId},
    ///     kad::KademliaEvent,
    ///     request_response::{RequestId, RequestResponseEvent, ResponseChannel},
    /// };
    ///
    /// let local_keys = Keypair::generate_ed25519();
    ///
    /// struct Handler();
    /// impl InboundEventCodec for Handler {
    ///     fn handle_request_response_event(
    ///         _swarm: &mut impl SwarmContext,
    ///         _event: RequestResponseEvent<Request, Response>,
    ///     ) {
    ///     }
    ///
    ///     fn handle_kademlia_event(_swarm: &mut impl SwarmContext, _result: KademliaEvent) {}
    /// }
    ///
    /// let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public()).unwrap();
    /// let mut network = P2PNetwork::new(behaviour, local_keys).unwrap();
    /// ```
    pub fn new(behaviour: P2PNetworkBehaviour<C>, local_keys: Keypair) -> QueryResult<Self> {
        let peer_id = PeerId::from(local_keys.public());
        let transport = build_development_transport(local_keys)
            .map_err(|_| QueryError::ConnectionError("Could not build transport layer".to_string()))?;
        let swarm: P2PNetworkSwarm<C> = Swarm::new(transport, behaviour, peer_id.clone());
        Ok(P2PNetwork::<C> {
            peer_id,
            #[cfg(feature = "kademlia")]
            mailboxes: None,
            swarm,
        })
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn start_listening(&mut self, listening_addr: Option<Multiaddr>) -> QueryResult<ListenerId> {
        let addr = listening_addr
            .or_else(|| Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").ok())
            .ok_or_else(|| QueryError::ConnectionError("Invalid Multiaddr".to_string()))?;
        Swarm::listen_on(&mut self.swarm, addr).map_err(|e| QueryError::ConnectionError(format!("{}", e)))
    }

    /// Add a remote peer to the kademlia bucket
    #[cfg(feature = "kademlia")]
    pub fn connect_remote(&mut self, _peer_id: PeerId, peer_addr: Multiaddr) -> QueryResult<()> {
        self.swarm.kad_add_address(&_peer_id, peer_addr);
        self.swarm
            .kad_bootstrap()
            .map_err(|_| QueryError::KademliaError(format!("Could not bootstrap {}", _peer_id)))?;
        Ok(())
    }

    /// Dials a peer if it is either in the same network or has a public IP Address
    pub fn dial_addr(&mut self, peer_addr: Multiaddr) -> QueryResult<()> {
        Swarm::dial_addr(&mut self.swarm, peer_addr.clone())
            .map_err(|_| QueryError::ConnectionError(format!("Could not dial addr {}", peer_addr)))
    }

    /// Prints the multi-addresses that this peer is listening on within the local network.
    pub fn get_listeners(&self) -> impl Iterator<Item = &Multiaddr> {
        Swarm::listeners(&self.swarm)
    }

    #[cfg(feature = "kademlia")]
    pub fn add_mailbox(&mut self, mailbox_peer: PeerId, mailbox_addr: Multiaddr) -> QueryResult<()> {
        self.connect_remote(mailbox_peer.clone(), mailbox_addr.clone())?;
        if let Some(mailboxes) = self.mailboxes.as_mut() {
            mailboxes.add_mailbox(mailbox_peer, mailbox_addr);
        } else {
            self.mailboxes = Some(Mailboxes::new(mailbox_peer, mailbox_addr));
        }
        Ok(())
    }

    #[cfg(feature = "kademlia")]
    pub fn get_default_mailbox(&self) -> Option<&PeerId> {
        self.mailboxes.as_ref().map(|mailboxes| mailboxes.get_default())
    }

    #[cfg(feature = "kademlia")]
    pub fn set_default_mailbox(&mut self, mailbox_peer: PeerId) -> QueryResult<()> {
        let mut mailboxes = self
            .mailboxes
            .clone()
            .ok_or_else(|| QueryError::Mailbox("No known mailboxes".to_string()))?;
        mailboxes.set_default(mailbox_peer)?;
        self.mailboxes = Some(mailboxes);
        Ok(())
    }

    #[cfg(feature = "kademlia")]
    pub fn get_all_mailboxes(&self) -> Option<Vec<PeerId>> {
        self.mailboxes
            .clone()
            .map(|mut m| m.get_mailboxes().keys().cloned().collect())
    }

    #[cfg(feature = "kademlia")]
    pub fn find_mailbox(&self, mailbox_peer: PeerId) -> Option<(&PeerId, &Multiaddr)> {
        self.mailboxes
            .as_ref()
            .and_then(|mailboxes| mailboxes.find_mailbox(&mailbox_peer))
    }

    /// Send a publish request to the mailbox in order to make information available for a peer that can not
    /// be dialed directly. If no `mailbox_peer_id` is provided, the default mailbox is used.
    #[cfg(feature = "kademlia")]
    pub fn put_record_mailbox(
        &mut self,
        record: MailboxRecord,
        mailbox_peer_id: Option<PeerId>,
    ) -> QueryResult<RequestId> {
        let mailboxes = self
            .mailboxes
            .clone()
            .ok_or_else(|| QueryError::Mailbox("No known mailboxes".to_string()))?;
        let peer = if let Some(peer_id) = mailbox_peer_id {
            mailboxes
                .find_mailbox(&peer_id)
                .map(|(peer_id, _)| peer_id)
                .ok_or_else(|| QueryError::Mailbox(format!("No know mailbox for {}", peer_id)))
        } else {
            Ok(mailboxes.get_default())
        }?;
        Ok(self.swarm.send_request(peer, Request::Publish(record)))
    }
}

#[cfg(test)]
struct DummyHandler;
#[cfg(test)]
impl InboundEventCodec for DummyHandler {
    fn handle_request_response_event(_swarm: &mut impl SwarmContext, _event: RequestResponseEvent<Request, Response>) {}
    fn handle_kademlia_event(_swarm: &mut impl SwarmContext, _result: KademliaEvent) {}
}

#[cfg(test)]
fn mock_network() -> P2PNetwork<DummyHandler> {
    let local_keys = Keypair::generate_ed25519();
    let behaviour = P2PNetworkBehaviour::<DummyHandler>::new(local_keys.public()).unwrap();
    P2PNetwork::new(behaviour, local_keys).unwrap()
}

#[cfg(test)]
fn mock_addr() -> Multiaddr {
    Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap()
}

#[test]
fn test_new_network() {
    let local_keys = Keypair::generate_ed25519();
    let behaviour = P2PNetworkBehaviour::<DummyHandler>::new(local_keys.public()).unwrap();
    let network = P2PNetwork::new(behaviour, local_keys.clone()).unwrap();
    assert_eq!(&PeerId::from_public_key(local_keys.public()), network.local_peer_id());
    assert!(network.get_all_mailboxes().is_none());
}

#[test]
fn test_add_mailbox() {
    let mut network = mock_network();
    let peer_id = PeerId::random();
    network.add_mailbox(peer_id.clone(), mock_addr()).unwrap();
    assert!(network.find_mailbox(peer_id.clone()).is_some());
    assert!(network.get_all_mailboxes().unwrap().contains(&peer_id));
}

#[test]
fn test_default_mailbox() {
    let mut network = mock_network();
    assert!(network.get_default_mailbox().is_none());

    let peer_id_1 = PeerId::random();
    assert!(network.set_default_mailbox(peer_id_1.clone()).is_err());
    network.add_mailbox(peer_id_1.clone(), mock_addr()).unwrap();
    assert_eq!(network.get_default_mailbox().unwrap(), &peer_id_1);

    let peer_id_2 = PeerId::random();
    assert!(network.set_default_mailbox(peer_id_2.clone()).is_err());
    network.add_mailbox(peer_id_2.clone(), mock_addr()).unwrap();
    assert_eq!(network.get_default_mailbox().unwrap(), &peer_id_1);
    assert!(network.set_default_mailbox(peer_id_2.clone()).is_ok());
    assert_eq!(network.get_default_mailbox().unwrap(), &peer_id_2);
}

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

mod protocol;
#[cfg(any(feature = "kademlia", feature ="mdns"))]
use crate::error::QueryError;
#[cfg(feature = "kademlia")]
use crate::message::MailboxRecord;
use crate::{
    error::QueryResult,
    message::{Request, Response},
};
#[cfg(feature = "kademlia")]
use core::time::Duration;
use core::{iter, marker::PhantomData};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsEvent};
#[cfg(feature = "kademlia")]
use libp2p::{
    core::Multiaddr,
    kad::{record::Key, store::MemoryStore, Addresses, Kademlia, KademliaEvent, QueryId, Quorum, Record as KadRecord},
};
use libp2p::{
    core::PeerId,
    identity::PublicKey,
    request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig, RequestResponseEvent, ResponseChannel,
    },
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour,
};
use protocol::{MessageCodec, MessageProtocol};
// TODO: support no_std
#[cfg(feature = "kademlia")]
use std::collections::BTreeMap;
use std::marker::Send;
#[cfg(feature = "kademlia")]
use std::time::Instant;

/// Interface for the communication with the swarm
pub trait SwarmContext {
    fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId;

    fn send_response(&mut self, response: Response, channel: ResponseChannel<Response>);

    #[cfg(feature = "kademlia")]
    fn get_record(&mut self, key_str: String) -> QueryId;

    #[cfg(feature = "kademlia")]
    fn put_record_local(&mut self, record: MailboxRecord) -> QueryResult<QueryId>;

    #[cfg(feature = "kademlia")]
    fn get_kademlia_peers(&mut self) -> BTreeMap<PeerId, Addresses>;

    #[cfg(feature = "mdns")]
    fn get_active_mdns_peers(&mut self) -> Vec<PeerId>;

    #[cfg(feature = "kademlia")]
    fn kad_add_address(&mut self, peer_id: &PeerId, addr: Multiaddr);

    #[cfg(feature = "kademlia")]
    fn kad_bootstrap(&mut self) -> QueryResult<QueryId>;
}

/// Codec that describes a custom behaviour for inbound events from the swarm.
pub trait InboundEventCodec {
    fn handle_request_response_event(swarm: &mut impl SwarmContext, event: RequestResponseEvent<Request, Response>);
    #[cfg(feature = "kademlia")]
    fn handle_kademlia_event(swarm: &mut impl SwarmContext, result: KademliaEvent);
}

#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour<C: InboundEventCodec + Send + 'static> {
    #[cfg(feature = "kademlia")]
    kademlia: Kademlia<MemoryStore>,
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    msg_proto: RequestResponse<MessageCodec>,
    #[behaviour(ignore)]
    inner: PhantomData<C>,
}

impl<C: InboundEventCodec + Send + 'static> SwarmContext for P2PNetworkBehaviour<C> {
    fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId {
        self.msg_proto.send_request(peer_id, request)
    }

    fn send_response(&mut self, response: Response, channel: ResponseChannel<Response>) {
        self.msg_proto.send_response(channel, response)
    }

    /// Fetch a record from the kademlia DHT of a known peer
    #[cfg(feature = "kademlia")]
    fn get_record(&mut self, key_str: String) -> QueryId {
        let key = Key::new(&key_str);
        self.kademlia.get_record(&key, Quorum::One)
    }

    /// Publish a record in own Kademlia DHT
    #[cfg(feature = "kademlia")]
    fn put_record_local(&mut self, record: MailboxRecord) -> QueryResult<QueryId> {
        let record = KadRecord {
            key: Key::new(&record.key()),
            value: record.value().into_bytes(),
            publisher: None,
            expires: Some(Instant::now() + Duration::from_secs(record.expires_sec())),
        };
        self.kademlia
            .put_record(record, Quorum::One)
            .map_err(|_| QueryError::KademliaError("Can not store record".to_string()))
    }

    #[cfg(feature = "kademlia")]
    /// Get the discovered peers from kademlia buckets. mDNS peers are automatically added to kademlia too.
    fn get_kademlia_peers(&mut self) -> BTreeMap<PeerId, Addresses> {
        let mut map = BTreeMap::new();
        for bucket in self.kademlia.kbuckets() {
            for entry in bucket.iter() {
                map.insert(entry.node.key.preimage().clone(), entry.node.value.clone());
            }
        }
        map
    }

    #[cfg(feature = "mdns")]
    /// Get the peers discovered by mdns
    fn get_active_mdns_peers(&mut self) -> Vec<PeerId> {
        let mut peers = Vec::new();
        for peer_id in self.mdns.discovered_nodes() {
            peers.push(peer_id.clone());
        }
        peers
    }

    /// Add a remote peer's listening address for their PeerId to the kademlia buckets
    /// This is necessary for initiating communication with peers that are not known yet.
    #[cfg(feature = "kademlia")]
    fn kad_add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        self.kademlia.add_address(peer_id, addr);
    }

    /// Uses libp2p's Kademlia to bootstrap the local node to join the DHT.
    ///
    /// Bootstrapping is a multi-step operation that starts with a lookup of the local node's
    /// own ID in the DHT. This introduces the local node to the other nodes
    /// in the DHT and populates its routing table with the closest neighbours.
    ///
    /// Subsequently, all buckets farther from the bucket of the closest neighbour are
    /// refreshed by initiating an additional bootstrapping query for each such
    /// bucket with random keys.
    ///
    /// Returns `Ok` if bootstrapping has been initiated with a self-lookup, providing the
    /// `QueryId` for the entire bootstrapping process. The progress of bootstrapping is
    /// reported via [`KademliaEvent::QueryResult{QueryResult::Bootstrap}`] events,
    /// with one such event per bootstrapping query.
    ///
    /// Returns `Err` if bootstrapping is impossible due an empty routing table.
    ///
    /// > **Note**: Bootstrapping requires at least one node of the DHT to be known.
    /// > See libp2p [`Kademlia::add_address`].
    #[cfg(feature = "kademlia")]
    fn kad_bootstrap(&mut self) -> QueryResult<QueryId> {
        self.kademlia
            .bootstrap()
            .map_err(|e| QueryError::KademliaError(format!("Could not bootstrap:{:?}", e.to_string())))
    }
}

impl<C: InboundEventCodec + Send + 'static> P2PNetworkBehaviour<C> {
    /// Creates a new P2PNetworkbehaviour that defines the communication with the libp2p swarm.
    /// It combines the following protocols from libp2p:
    /// - mDNS for peer discovery within the local network
    /// - RequestResponse Protocol for sending request and reponse messages. This stronghold-communication library
    ///   defines a custom version of this protocol that for sending pings, string-messages and key-value-records.
    /// - kademlia (if the "kademlia"-feature is enabled) for managing peer in kademlia buckets and publishing/ reading
    ///   records
    ///
    /// # Example
    /// ```no_run
    /// use communication::{
    ///     behaviour::{InboundEventCodec, P2PNetworkBehaviour, SwarmContext},
    ///     error::QueryResult,
    ///     message::{Request, Response},
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
    /// ```
    pub fn new(public_key: PublicKey) -> QueryResult<Self> {
        #[allow(unused_variables)]
        let peer_id = PeerId::from(public_key);
        #[cfg(feature = "kademlia")]
        let kademlia = {
            let store = MemoryStore::new(peer_id.clone());
            Kademlia::new(peer_id, store)
        };

        #[cfg(feature = "mdns")]
        let mdns =
            Mdns::new().map_err(|_| QueryError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        // Create RequestResponse behaviour with MessageProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec(), protocols, cfg)
        };

        Ok(P2PNetworkBehaviour::<C> {
            #[cfg(feature = "kademlia")]
            kademlia,
            #[cfg(feature = "mdns")]
            mdns,
            msg_proto,
            inner: PhantomData,
        })
    }
}

#[cfg(feature = "mdns")]
impl<C: InboundEventCodec + Send + 'static> NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour<C> {
    // Called when `mdns` produces an event.
    #[allow(unused_variables)]
    fn inject_event(&mut self, event: MdnsEvent) {
        #[cfg(feature = "kademlia")]
        if let MdnsEvent::Discovered(list) = event {
            for (peer_id, multiaddr) in list {
                self.kademlia.add_address(&peer_id, multiaddr);
            }
        }
    }
}

#[cfg(feature = "kademlia")]
impl<C: InboundEventCodec + Send + 'static> NetworkBehaviourEventProcess<KademliaEvent> for P2PNetworkBehaviour<C> {
    // Called when `kademlia` produces an event.
    fn inject_event(&mut self, message: KademliaEvent) {
        C::handle_kademlia_event(self, message);
    }
}

impl<C: InboundEventCodec + Send + 'static> NetworkBehaviourEventProcess<RequestResponseEvent<Request, Response>>
    for P2PNetworkBehaviour<C>
{
    // Called when the protocol produces an event.
    fn inject_event(&mut self, event: RequestResponseEvent<Request, Response>) {
        C::handle_request_response_event(self, event);
    }
}

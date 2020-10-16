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

pub mod codec;
mod protocol;
use crate::error::{QueryError, QueryResult};
#[cfg(feature = "kademlia")]
use crate::message::MailboxRecord;
use crate::message::{Request, Response};
use codec::{Codec, CodecContext};
use core::iter;
#[cfg(feature = "kademlia")]
use core::time::Duration;
#[cfg(feature = "kademlia")]
use libp2p::{
    core::Multiaddr,
    kad::{record::Key, store::MemoryStore, Kademlia, KademliaEvent, QueryId, Quorum, Record as KadRecord},
};
use libp2p::{
    core::PeerId,
    mdns::{Mdns, MdnsEvent},
    request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig,
        RequestResponseEvent::{self, InboundFailure, Message as MessageEvent, OutboundFailure},
        RequestResponseMessage, ResponseChannel,
    },
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour,
};
use protocol::{MessageCodec, MessageProtocol};
// TODO: support no_std
use std::marker::Send;
#[cfg(feature = "kademlia")]
use std::time::Instant;

#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour<C: Codec + Send + 'static> {
    #[cfg(feature = "kademlia")]
    kademlia: Kademlia<MemoryStore>,
    mdns: Mdns,
    msg_proto: RequestResponse<MessageCodec>,
    #[behaviour(ignore)]
    #[allow(dead_code)]
    inner: C,
}

impl<C: Codec + Send + 'static> CodecContext for P2PNetworkBehaviour<C> {
    fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId {
        self.msg_proto.send_request(peer_id, request)
    }

    fn send_response(&mut self, response: Response, channel: ResponseChannel<Response>) {
        self.msg_proto.send_response(channel, response)
    }

    #[cfg(feature = "kademlia")]
    fn get_record(&mut self, key_str: String) -> QueryId {
        let key = Key::new(&key_str);
        self.kademlia.get_record(&key, Quorum::One)
    }

    #[cfg(feature = "kademlia")]
    fn put_record_local(&mut self, record: MailboxRecord) -> QueryResult<QueryId> {
        let record = KadRecord {
            key: Key::new(&record.key()),
            value: record.value().into_bytes(),
            publisher: None,
            expires: Some(Instant::now() + Duration::from_secs(record.timeout_sec())),
        };
        self.kademlia
            .put_record(record, Quorum::One)
            .map_err(|_| QueryError::KademliaError("Can not store record".to_string()))
    }

    fn print_known_peers(&mut self) {
        println!("Known peers:");
        #[cfg(feature = "kademlia")]
        for bucket in self.kademlia.kbuckets() {
            for entry in bucket.iter() {
                println!("key: {:?}, values: {:?}", entry.node.key.preimage(), entry.node.value);
            }
        }
        #[cfg(not(feature = "kademlia"))]
        for peer_id in self.mdns.discovered_nodes() {
            println!("{:?}", peer_id);
        }
    }

    #[cfg(feature = "kademlia")]
    fn kad_add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        self.kademlia.add_address(peer_id, addr);
    }

    #[cfg(feature = "kademlia")]
    fn kad_bootstrap(&mut self) -> QueryResult<QueryId> {
        self.kademlia
            .bootstrap()
            .map_err(|e| QueryError::KademliaError(format!("Could not bootstrap:{:?}", e.to_string())))
    }
}

impl<C: Codec + Send + 'static> P2PNetworkBehaviour<C> {
    #[cfg(not(feature = "kademlia"))]
    pub fn new(_peer_id: PeerId, inner: C) -> QueryResult<Self> {
        let mdns =
            Mdns::new().map_err(|_| QueryError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        // Create RequestResponse behaviour with MessageProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec(), protocols, cfg)
        };

        Ok(P2PNetworkBehaviour::<C> { mdns, msg_proto, inner })
    }

    #[cfg(feature = "kademlia")]
    pub fn new(peer_id: PeerId, inner: C) -> QueryResult<Self> {
        let kademlia = {
            let store = MemoryStore::new(peer_id.clone());
            Kademlia::new(peer_id, store)
        };
        let mdns =
            Mdns::new().map_err(|_| QueryError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        // Create RequestResponse behaviour with MessageProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec(), protocols, cfg)
        };

        Ok(P2PNetworkBehaviour::<C> {
            kademlia,
            mdns,
            msg_proto,
            inner,
        })
    }
}

impl<C: Codec + Send + 'static> NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour<C> {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, _event: MdnsEvent) {
        #[cfg(feature = "kademlia")]
        if let MdnsEvent::Discovered(list) = _event {
            for (peer_id, multiaddr) in list {
                self.kademlia.add_address(&peer_id, multiaddr);
            }
        }
    }
}

#[cfg(feature = "kademlia")]
impl<C: Codec + Send + 'static> NetworkBehaviourEventProcess<KademliaEvent> for P2PNetworkBehaviour<C> {
    // Called when `kademlia` produces an event.
    fn inject_event(&mut self, message: KademliaEvent) {
        C::handle_kademlia_event(self, message);
    }
}

impl<C: Codec + Send + 'static> NetworkBehaviourEventProcess<RequestResponseEvent<Request, Response>>
    for P2PNetworkBehaviour<C>
{
    // Called when the protocol produces an event.
    fn inject_event(&mut self, event: RequestResponseEvent<Request, Response>) {
        match event {
            MessageEvent { peer: _, message } => match message {
                RequestResponseMessage::Request {
                    request_id: _,
                    request,
                    channel,
                } => C::handle_request_msg(self, request, channel),
                RequestResponseMessage::Response { request_id, response } => {
                    C::handle_response_msg(self, response, request_id)
                }
            },
            OutboundFailure {
                peer,
                request_id,
                error,
            } => println!(
                "Outbound Failure for request {:?} to peer: {:?}: {:?}.",
                request_id, peer, error
            ),
            InboundFailure {
                peer,
                request_id,
                error,
            } => println!(
                "Inbound Failure for request {:?} to peer: {:?}: {:?}.",
                request_id, peer, error
            ),
        }
    }
}

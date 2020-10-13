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

use crate::codec::{Codec, CodecContext};
use crate::error::{P2PError, P2PResult};
use crate::protocol::{MailboxCodec, MailboxProtocol, MailboxRequest, MailboxResponse};
use core::iter;
#[cfg(feature = "kademlia")]
use core::time::Duration;
#[cfg(feature = "kademlia")]
use libp2p::kad::{
    record::Key, store::MemoryStore, Kademlia, KademliaEvent, PeerRecord, QueryId, QueryResult, Quorum, Record,
};
use libp2p::{
    core::PeerId,
    mdns::{Mdns, MdnsEvent},
    request_response::{
        ProtocolSupport, RequestResponse, RequestResponseConfig,
        RequestResponseEvent::{self, InboundFailure, Message as MessageEvent, OutboundFailure},
        RequestResponseMessage::{Request, Response},
        ResponseChannel,
    },
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour,
};
// TODO: support no_std
use std::marker::Send;
#[cfg(feature = "kademlia")]
use std::time::Instant;

#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour<C, Ctx>
where
    C: Codec + Send + 'static,
    Ctx: CodecContext + Send + 'static,
{
    #[cfg(feature = "kademlia")]
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) mdns: Mdns,
    pub(crate) msg_proto: RequestResponse<MailboxCodec>,
    #[behaviour(ignore)]
    timeout_sec: Duration,
    #[behaviour(ignore)]
    inner: Ctx,
}

impl<C, Ctx> CodecContext for P2PNetworkBehaviour<C, Ctx> {
    fn send_request(&mut self, peer_id: PeerId, request: MailboxRequest) {
        self.msg_proto.send_request(&peer_id, request);
    }

    fn send_response(&mut self, response: MailboxResponse, channel: ResponseChannel<MailboxResponse>) {
        self.msg_proto.send_response(channel, response)
    }

    #[cfg(feature = "kademlia")]
    fn get_record(&mut self, key_str: String) {
        let key = Key::new(&key_str);
        self.kademlia.get_record(&key, Quorum::One);
    }

    #[cfg(feature = "kademlia")]
    fn put_record_local(
        &mut self,
        key_str: String,
        value_str: String,
        timeout_sec: Option<Duration>,
    ) -> P2PResult<QueryId> {
        let duration = timeout_sec.filter(|s| s.as_secs() > 0).unwrap_or(self.timeout_sec);
        let record = Record {
            key: Key::new(&key_str),
            value: value_str.into_bytes(),
            publisher: None,
            expires: Some(Instant::now() + duration),
        };
        self.kademlia
            .put_record(record, Quorum::One)
            .map_err(|_| P2PError::KademliaError("Can not store record".to_string()))
    }
}

/* impl<C: Codec + Send + 'static> Codec for P2PNetworkBehaviour<C> {
    fn handle_request_msg<Ctx: CodecContext>(
        ctx: &mut Ctx,
        request: MailboxRequest,
        channel: ResponseChannel<MailboxResponse>,
    ) {
        match request {
            MailboxRequest::Ping => {
                println!("Received Ping, we will send a Pong back.");
                ctx.send_response(MailboxResponse::Pong, channel);
            }
            #[cfg(feature = "kademlia")]
            MailboxRequest::Publish(r) => {
                let duration = Some(Duration::from_secs(r.timeout_sec));
                let query_id = ctx.put_record_local(r.key, r.value, duration);
                if query_id.is_ok() {
                    println!("Successfully stored record.");
                    ctx.send_response(MailboxResponse::Publish(MailboxResult::Success), channel);
                } else {
                    println!("Error storing record: {:?}", query_id.err());
                }
            }
            MailboxRequest::Message(msg) => {
                println!("Received Message {:?}.", msg);
            }
        }
    }

    fn handle_response_msg<Ctx: CodecContext>(_ctx: &mut Ctx, response: MailboxResponse, request_id: RequestId) {
        match response {
            MailboxResponse::Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            #[cfg(feature = "kademlia")]
            MailboxResponse::Publish(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
        }
    }
} */

impl<C: Codec + Send + 'static, Ctx: CodecContext + Send + 'static> P2PNetworkBehaviour<C, Ctx> {
    pub fn new(peer_id: PeerId, timeout_sec: Duration, inner: C) -> P2PResult<Self> {
        #[cfg(feature = "kademlia")]
        let kademlia = {
            let store = MemoryStore::new(peer_id.clone());
            Kademlia::new(peer_id, store)
        };
        let mdns = Mdns::new().map_err(|_| P2PError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        // Create RequestResponse behaviour with MailboxProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MailboxProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MailboxCodec(), protocols, cfg)
        };

        Ok(P2PNetworkBehaviour::<C, Ctx> {
            #[cfg(feature = "kademlia")]
            kademlia,
            mdns,
            msg_proto,
            timeout_sec,
            inner,
        })
    }
}

impl<C: Codec + Send + 'static, Ctx: CodecContext + Send + 'static>  NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour<C, Ctx> {
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
impl<C: Codec + Send + 'static, Ctx: CodecContext + Send + 'static> NetworkBehaviourEventProcess<KademliaEvent> for P2PNetworkBehaviour<C, Ctx> {
    // Called when `kademlia` produces an event.
    fn inject_event(&mut self, message: KademliaEvent) {
        if let KademliaEvent::QueryResult { result, .. } = message {
            match result {
                QueryResult::GetRecord(Ok(ok)) => {
                    for PeerRecord {
                        record: Record { key, value, .. },
                        ..
                    } in ok.records
                    {
                        println!(
                            "Got record {:?} {:?}.",
                            std::str::from_utf8(key.as_ref()).unwrap(),
                            std::str::from_utf8(&value).unwrap(),
                        );
                    }
                }
                QueryResult::GetRecord(Err(err)) => {
                    eprintln!("Failed to get record: {:?}.", err);
                }
                _ => {}
            }
        }
    }
}

impl<C: Codec + Send + 'static, Ctx: CodecContext + Send + 'static>  NetworkBehaviourEventProcess<RequestResponseEvent<MailboxRequest, MailboxResponse>>
    for P2PNetworkBehaviour<C, Ctx>
{
    // Called when the protocol produces an event.
    fn inject_event(&mut self, event: RequestResponseEvent<MailboxRequest, MailboxResponse>) {
        match event {
            MessageEvent { peer: _, message } => match message {
                Request {
                    request_id: _,
                    request,
                    channel,
                } => P2PNetworkBehaviour::<C>::handle_request_msg::<Ctx>(&mut self.inner, request, channel),
                Response { request_id, response } => Codec::handle_response_msg(self, response, request_id),
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

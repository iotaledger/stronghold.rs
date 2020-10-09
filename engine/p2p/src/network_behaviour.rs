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

use crate::mailbox_protocol::{
    MailboxCodec,
    MailboxRequest::{self, Message as ReqMessage, Ping},
    MailboxResponse::{self, Pong},
};
#[cfg(feature = "kademlia")]
use crate::mailbox_protocol::{MailboxRequest::Publish as PubReq, MailboxResponse::Publish as PubRes, MailboxResult};
#[cfg(feature = "kademlia")]
use core::time::Duration;
#[cfg(feature = "kademlia")]
use libp2p::kad::{record::Key, store::MemoryStore, Kademlia, KademliaEvent, PeerRecord, QueryResult, Quorum, Record};
use libp2p::{
    mdns::{Mdns, MdnsEvent},
    request_response::{
        RequestId, RequestResponse,
        RequestResponseEvent::{self, InboundFailure, Message as MessageEvent, OutboundFailure},
        RequestResponseMessage::{Request, Response},
        ResponseChannel,
    },
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour,
};
#[cfg(feature = "kademlia")]
// TODO: support no_std
use std::time::Instant;

#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour {
    #[cfg(feature = "kademlia")]
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) mdns: Mdns,
    pub(crate) msg_proto: RequestResponse<MailboxCodec>,
}

impl P2PNetworkBehaviour {
    fn handle_request_msg(&mut self, request: MailboxRequest, channel: ResponseChannel<MailboxResponse>) {
        match request {
            Ping => {
                println!("Received Ping, we will send a Pong back.");
                self.msg_proto.send_response(channel, Pong);
            }
            #[cfg(feature = "kademlia")]
            PubReq(r) => {
                let duration = if r.timeout_sec > 0 { r.timeout_sec } else { 9000u64 };
                let record = Record {
                    key: Key::new(&r.key),
                    value: r.value.into_bytes(),
                    publisher: None,
                    expires: Some(Instant::now() + Duration::new(duration, 0)),
                };
                let put_record = self.kademlia.put_record(record, Quorum::One);
                if put_record.is_ok() {
                    println!("Successfully stored record.");
                    self.msg_proto.send_response(channel, PubRes(MailboxResult::Success));
                } else {
                    println!("Error storing record: {:?}", put_record.err());
                }
            }
            ReqMessage(msg) => {
                println!("Received Message {:?}.", msg);
            }
        }
    }

    fn handle_response_msg(&mut self, response: MailboxResponse, request_id: RequestId) {
        match response {
            Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            #[cfg(feature = "kademlia")]
            PubRes(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour {
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
impl NetworkBehaviourEventProcess<KademliaEvent> for P2PNetworkBehaviour {
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

impl NetworkBehaviourEventProcess<RequestResponseEvent<MailboxRequest, MailboxResponse>> for P2PNetworkBehaviour {
    // Called when the mailbox_protocol produces an event.
    fn inject_event(&mut self, event: RequestResponseEvent<MailboxRequest, MailboxResponse>) {
        match event {
            MessageEvent { peer: _, message } => match message {
                Request {
                    request_id: _,
                    request,
                    channel,
                } => self.handle_request_msg(request, channel),
                Response { request_id, response } => self.handle_response_msg(response, request_id),
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

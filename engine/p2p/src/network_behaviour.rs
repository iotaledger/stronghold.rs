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
    MailboxRequest::{self, Ping, Publish as PubReq},
    MailboxResponse::{self, Pong, Publish as PubRes},
    MailboxResult,
};
use libp2p::{
    kad::{record::Key, store::MemoryStore, Kademlia, KademliaEvent, PeerRecord, QueryResult, Quorum, Record},
    mdns::{Mdns, MdnsEvent},
    request_response::{
        RequestId, RequestResponse,
        RequestResponseEvent::{self, InboundFailure, Message, OutboundFailure},
        RequestResponseMessage::{Request, Response},
        ResponseChannel,
    },
    swarm::NetworkBehaviourEventProcess,
    NetworkBehaviour,
};
use std::time::{Duration, Instant};

#[derive(NetworkBehaviour)]
pub struct P2PNetworkBehaviour {
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) mdns: Mdns,
    pub(crate) msg_proto: RequestResponse<MailboxCodec>,
}

impl NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        if let MdnsEvent::Discovered(list) = event {
            for (peer_id, multiaddr) in list {
                self.kademlia.add_address(&peer_id, multiaddr);
            }
        }
    }
}

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
            Message { peer: _, message } => match message {
                Request {
                    request_id: _,
                    request,
                    channel,
                } => self.handle_request_msg(request, channel),
                Response { request_id, response } => self.handle_response_msg(request_id, response),
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

impl P2PNetworkBehaviour {
    fn handle_request_msg(&mut self, request: MailboxRequest, channel: ResponseChannel<MailboxResponse>) {
        match request {
            Ping => {
                println!("Received Ping, we will send a Pong back.");
                self.msg_proto.send_response(channel, Pong);
            }
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
        }
    }

    fn handle_response_msg(&mut self, request_id: RequestId, response: MailboxResponse) {
        match response {
            Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            PubRes(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
        }
    }
}

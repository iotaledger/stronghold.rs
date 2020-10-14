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

use async_std::task;
use clap::{load_yaml, App, ArgMatches};
use communication::{
    behaviour::{
        codec::{Codec, CodecContext},
        P2PNetworkBehaviour,
    },
    protocol::{MessageResult, Request, Response},
    P2PNetwork,
};
use core::{str::FromStr, time::Duration};
use libp2p::{
    core::{identity::Keypair, Multiaddr, PeerId},
    request_response::{RequestId, ResponseChannel},
    swarm::SwarmEvent,
};

#[cfg(feature = "kademlia")]
use libp2p::kad::{KademliaEvent, PeerRecord, QueryResult as KadQueryResult, Record as KadRecord};

struct Handler();

impl Codec for Handler {
    fn handle_request_msg(ctx: &mut impl CodecContext, request: Request, channel: ResponseChannel<Response>) {
        match request {
            Request::Ping => {
                println!("Received Ping, we will send a Pong back.");
                ctx.send_response(Response::Pong, channel);
            }
            #[cfg(feature = "kademlia")]
            Request::Publish(r) => {
                let duration = Some(Duration::from_secs(r.timeout_sec()));
                let query_id = ctx.put_record_local(r.key(), r.value(), duration);
                if query_id.is_ok() {
                    println!("Successfully stored record.");
                    ctx.send_response(Response::Result(MessageResult::Success), channel);
                } else {
                    println!("Error storing record: {:?}", query_id.err());
                }
            }
            Request::Message(msg) => {
                println!("Received Message {:?}.", msg);
            }
        }
    }

    fn handle_response_msg(_ctx: &mut impl CodecContext, response: Response, request_id: RequestId) {
        match response {
            Response::Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            #[cfg(feature = "kademlia")]
            Response::Result(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
        }
    }

    #[cfg(feature = "kademlia")]
    fn handle_kademlia_event(_ctx: &mut impl CodecContext, event: KademliaEvent){
        if let KademliaEvent::QueryResult { result, .. } = event {
            match result {
                KadQueryResult::GetRecord(Ok(ok)) => {
                    for PeerRecord {
                        record: KadRecord { key, value, .. },
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
                KadQueryResult::GetRecord(Err(err)) => {
                    eprintln!("Failed to get record: {:?}.", err);
                }
                _ => {}
            }
        }
    }
}

// Put a record into the mailbox
fn put_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("put_mailbox") {
        if let Some(mail_id) = matches
            .value_of("mailbox_id")
            .and_then(|id_arg| PeerId::from_str(id_arg).ok())
        {
            if let Some(mail_addr) = matches
                .value_of("mailbox_addr")
                .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
            {
                if let Some(key) = matches.value_of("key") {
                    if let Some(value) = matches.value_of("value") {
                        let local_keys = Keypair::generate_ed25519();
                        let local_peer_id = PeerId::from(local_keys.public());
                        let timeout = matches
                            .value_of("timeout")
                            .and_then(|timeout| timeout.parse::<u64>().ok())
                            .map(Duration::from_secs);
                        let new_network =
                            P2PNetworkBehaviour::new(local_peer_id, timeout, Handler()).and_then(|behaviour| {
                                P2PNetwork::new(behaviour, local_keys, None, Some((mail_id, mail_addr)))
                            });
                        if let Ok(mut network) = new_network {
                            let request_id = network.put_record_mailbox(key.to_string(), value.to_string(), None, None);
                            if request_id.is_ok() {
                                task::block_on(async move {
                                    loop {
                                        if let SwarmEvent::ConnectionClosed { .. } = network.swarm.next_event().await {
                                            break;
                                        }
                                    }
                                });
                                return;
                            }
                        } else if let Err(e) = new_network {
                            eprintln!("Error creating Behaviour: {:?}", e);
                        }
                    }
                }
            }
        }
        eprintln!("Could not send record to mailbox");
    }
}

#[cfg(feature = "kademlia")]
// Get a record
fn get_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("get_record") {
        if let Some(mail_id) = matches
            .value_of("mailbox_id")
            .and_then(|id_arg| PeerId::from_str(id_arg).ok())
        {
            if let Some(mail_addr) = matches
                .value_of("mailbox_addr")
                .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
            {
                if let Some(key) = matches.value_of("key") {
                    let local_keys = Keypair::generate_ed25519();
                    let local_peer_id = PeerId::from(local_keys.public());
                    let new_network = P2PNetworkBehaviour::new(local_peer_id, None, Handler())
                        .and_then(|behaviour| P2PNetwork::new(behaviour, local_keys, None, Some((mail_id, mail_addr))));
                    if let Ok(mut network) = new_network {
                        network.swarm.get_record(key.to_string());
                        task::block_on(async move {
                            loop {
                                if let SwarmEvent::ConnectionClosed { .. } = network.swarm.next_event().await {
                                    break;
                                }
                            }
                        });
                        return;
                    } else if let Err(e) = new_network {
                        eprintln!("Error creating Behaviour: {:?}", e);
                    }
                }
            }
        }
        eprintln!("Could not send record to mailbox");
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    put_record(&matches);
    #[cfg(feature = "kademlia")]
    get_record(&matches);
}

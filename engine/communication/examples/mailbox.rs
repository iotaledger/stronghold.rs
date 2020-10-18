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
    error::QueryResult,
    message::{MailboxRecord, MessageResult, Request, Response},
    network::P2PNetwork,
};
use core::str::FromStr;
use libp2p::{
    core::{identity::Keypair, Multiaddr, PeerId},
    kad::{KademliaEvent, PeerRecord, QueryResult as KadQueryResult, Record as KadRecord},
    request_response::{RequestId, ResponseChannel},
    swarm::SwarmEvent,
};

struct Handler();


// Implement a Handler to determine the networks behaviour upon receiving messages and kademlia events. 
impl Codec for Handler {
    
    // Implements the mailbox behaviour by publishing records for others peers in kademlia. 
    fn handle_request_msg(ctx: &mut impl CodecContext, request: Request, channel: ResponseChannel<Response>, _peer: PeerId) {
        if let Request::Publish(r) = request {
            let record = MailboxRecord::new(r.key(), r.value(), r.timeout_sec());
            let query_id = ctx.put_record_local(record);
            if query_id.is_ok() {
                println!("Successfully stored record.");
                ctx.send_response(Response::Result(MessageResult::Success), channel);
            } else {
                println!("Error storing record: {:?}", query_id.err());
            }
        }
    }

    fn handle_response_msg(_ctx: &mut impl CodecContext, response: Response, request_id: RequestId, _peer: PeerId) {
        if let Response::Result(result) = response {
            println!("Received Result for publish request {:?}: {:?}.", request_id, result);
        }
    }

    fn handle_kademlia_event(_ctx: &mut impl CodecContext, event: KademliaEvent) {
        if let KademliaEvent::QueryResult { result, .. } = event {
            match result {
                // Triggers if the search for a record in kademlia was successful.
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
struct Matches {
    mail_id: PeerId,
    mail_addr: Multiaddr,
    key: String,
    value: Option<String>,
    timeout: Option<u64>,
}

// Match and parse the arguments from the CLI
fn eval_arg_matches(matches: &ArgMatches) -> Option<Matches> {
    if let Some(mail_id) = matches
        .value_of("mailbox_id")
        .and_then(|id_arg| PeerId::from_str(id_arg).ok())
    {
        if let Some(mail_addr) = matches
            .value_of("mailbox_addr")
            .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
        {
            if let Some(key) = matches.value_of("key").map(|k| k.to_string()) {
                let value = matches.value_of("value").map(|v| v.to_string());
                let timeout = matches
                    .value_of("timeout")
                    .and_then(|timeout| timeout.parse::<u64>().ok());
                return Some(Matches {
                    mail_id,
                    mail_addr,
                    key,
                    value,
                    timeout,
                });
            }
        }
    }
    None
}

// Put a record into the mailbox
fn put_record(matches: &ArgMatches) -> QueryResult<()> {
    if let Some(matches) = matches.subcommand_matches("put_mailbox") {
        if let Some(Matches {
            mail_id,
            mail_addr,
            key,
            value: Some(value),
            timeout,
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();

            // Create behaviour that uses the custom handler to describe how peers should react to events 
            // The P2PNetworkBehaviour implements the CodecContext trait for sending request and response messages and using the kademlia DHT
            let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public())?;
            // Create a network that implements the behaviour in it's swarm, and manages mailboxes and connections.
            let mut network = P2PNetwork::new(behaviour, local_keys, None)?;
            println!("Local PeerId: {:?}", network.local_peer_id());
            
            // Connect to a remote mailbox on the server.
            network.add_mailbox(mail_id.clone(), mail_addr)?;
            
            // Deposit a record on the mailbox
            // Triggers the Handler's handle_request_msg() Request::Publish(r) on the mailbox side.
            let record = MailboxRecord::new(key, value, timeout.unwrap_or(9000u64));
            let request_id = network.put_record_mailbox(record, Some(mail_id));

            if request_id.is_ok() {
                // Block until the connection is closed again due to timeout.
                task::block_on(async move {
                    loop {
                        if let SwarmEvent::ConnectionClosed { .. } = network.swarm.next_event().await {
                            break;
                        }
                    }
                });
            }
            
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
    Ok(())
}

// Get a record
fn get_record(matches: &ArgMatches) -> QueryResult<()> {
    if let Some(matches) = matches.subcommand_matches("get_record") {
        if let Some(Matches {
            mail_id,
            mail_addr,
            key,
            ..
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();

            // Create behaviour that uses the custom handler to describe how peers should react to events 
            // The P2PNetworkBehaviour implements the CodecContext trait for sending request and response messages and using the kademlia DHT
            let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public())?;
            // Create a network that implements the behaviour in it's swarm, and manages mailboxes and connections.
            let mut network = P2PNetwork::new(behaviour, local_keys, None)?;
            println!("Local PeerId: {:?}", network.local_peer_id());
            
            // Connect to a remote mailbox on the server.
            network.add_mailbox(mail_id.clone(), mail_addr)?;
                
            // Search for a record in the kademlia DHT. 
            // The search is successful if known peer has published a record and it is not expired.
            // Triggers the Handler's handle_kademlia_event() function.
            network.swarm.get_record(key);
            // Block until the connection is closed again due to timeout.
            task::block_on(async move {
                loop {
                    if let SwarmEvent::ConnectionClosed { .. } = network.swarm.next_event().await {
                        break;
                    }
                }
            });
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
    Ok(())
}

#[cfg(feature = "kademlia")]
fn main() -> QueryResult<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    put_record(&matches)?;
    get_record(&matches)?;
    Ok(())
}

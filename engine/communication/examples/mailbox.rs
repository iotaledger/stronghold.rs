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

//! This example implements the mailbox behaviour. It can be used to communicate with remote peers in different networks
//! that can not be dialed directly, e.g. because they are not listening to a public IP address.
//! Records for remote peers are sent to the mailbox that publishes it in it's kademlia DHT. 
//! The remote peer can then connect to the same mailbox and query kademlia for the record.
//!
//! In order for this example to work, the peer that serves as a mailbox has to obtain a public IP e.g. by running on
//! a server or by configuring port forwarding. For testing and dev purposes, IOTA currently maintains a server with
//! mailbox peer with `PeerId("12D3KooWHL8P9dFNRa7jEGfFz2BGw6RVwBQ3Gqdqy4UJCUG8d3p4)` in a docker container at the
//! address `"/dns/wrtc-star01.iota.cafe/tcp/16384"`.
//! 
//! # Deposit a record in the mailbox
//! 
//! ```sh
//! mailbox-put-mailbox 
//! Put record into the mailbox
//! 
//! USAGE:
//!     mailbox put_mailbox [OPTIONS] --mail-id <mailbox-peer-id> --mail-addr <mailbox-multi-addr> --key <record-key> --value <record-value>
//! 
//! OPTIONS:
//!     -e, --expires <expires-sec>             the expire seconds for the record
//!     -k, --key <record-key>                  the key for the record
//!     -a, --mail-addr <mailbox-multi-addr>    the multiaddr of the mailbox
//!     -i, --mail-id <mailbox-peer-id>         the peer id of the mailbox
//!     -v, --value <record-value>              the value for the record
//! ```
//! 
//! Using the above mailbox, a record can be deposited this mailbox could be done by running:
//! 
//! ```sh
//! $ cargo run --example mailbox -- put-mailbox  -i "12D3KooWHL8P9dFNRa7jEGfFz2BGw6RVwBQ3Gqdqy4UJCUG8d3p4" -a "/dns/wrtc-star01.iota.cafe/tcp/16384" -k "foo" -v "bar"
//! Local PeerId: PeerId("12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG")
//! Received Result for publish request RequestId(1): Success.
//! 
//! ```
//! 
//! Without the `--expires` argument, the record-expire default to 9000s.
//! 
//! # Reading a record
//! 
//! ```sh
//! mailbox-get-record 
//! Get record from local or the mailbox
//! 
//! USAGE:
//!     mailbox get-record --mail-id <mailbox-peer-id> --mail-addr <mailbox-multi-addr> --key <record-key>
//! 
//! OPTIONS:
//!     -k, --key <record-key>                  the key for the record
//!     -a, --mail-addr <mailbox-multi-addr>    the multi-address of the mailbox
//!     -i, --mail-id <mailbox-peer-id>         the peer id of the mailbox
//! ```
//! 
//! Using the above mailbox, a record is read from the mailbox by running
//! 
//! ```sh
//! $ cargo run --example mailbox -- get-record  -i "12D3KooWHL8P9dFNRa7jEGfFz2BGw6RVwBQ3Gqdqy4UJCUG8d3p4" -a "/dns/wrtc-star01.iota.cafe/tcp/16384" -k "foo"
//! Local PeerId: PeerId("12D3KooWJjtPjcMMa19WTnYvsmgpagPnDjSjeTgZS7j3YhwZX7Gn")
//! Got record "foo" "bar".
//! ```

use async_std::task;
use clap::{load_yaml, App, ArgMatches};
use communication::{
    behaviour::{InboundEventHandler, P2PNetworkBehaviour, SwarmContext},
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
impl InboundEventHandler for Handler {
    // Implements the mailbox behaviour by publishing records for others peers in the kademlia dht.
    fn handle_request_msg(
        swarm: &mut impl SwarmContext,
        request: Request,
        channel: ResponseChannel<Response>,
        _peer: PeerId,
    ) {
        if let Request::Publish(r) = request {
            let record = MailboxRecord::new(r.key(), r.value(), r.expires_sec());
            // store the record in the mailboxes kademlia dht
            let query_id = swarm.put_record_local(record);
            if query_id.is_ok() {
                println!("Successfully stored record.");
                swarm.send_response(Response::Result(MessageResult::Success), channel);
            } else {
                println!("Error storing record: {:?}", query_id.err());
            }
        }
    }

    fn handle_response_msg(_ctx: &mut impl SwarmContext, response: Response, request_id: RequestId, _peer: PeerId) {
        if let Response::Result(result) = response {
            println!("Received Result for publish request {:?}: {:?}.", request_id, result);
        }
    }

    fn handle_kademlia_event(_ctx: &mut impl SwarmContext, event: KademliaEvent) {
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

// only used for this CLI
struct Matches {
    mail_id: PeerId,
    mail_addr: Multiaddr,
    key: String,
    value: Option<String>,
    expires: Option<u64>,
}

// Match and parse the arguments from the command line
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
                let expires = matches
                    .value_of("expires")
                    .and_then(|expires| expires.parse::<u64>().ok());
                return Some(Matches {
                    mail_id,
                    mail_addr,
                    key,
                    value,
                    expires,
                });
            }
        }
    }
    None
}

// Deposit a record in the mailbox
fn put_record(matches: &ArgMatches) -> QueryResult<()> {
    if let Some(matches) = matches.subcommand_matches("put-mailbox") {
        if let Some(Matches {
            mail_id,
            mail_addr,
            key,
            value: Some(value),
            expires,
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();

            // Create behaviour that uses the custom Handler to describe how peers should react to events
            // The P2PNetworkBehaviour implements the SwarmContext trait for sending request and response messages and using the kademlia DHT
            let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public())?;
            // Create a network that implements the behaviour in it's swarm, and manages mailboxes and connections.
            let mut network = P2PNetwork::new(behaviour, local_keys, None)?;
            println!("Local PeerId: {:?}", network.local_peer_id());

            // Connect to a remote mailbox on the server.
            network.add_mailbox(mail_id.clone(), mail_addr)?;

            // Deposit a record on the mailbox
            // Triggers the Handler's handle_request_msg() Request::Publish(r) on the mailbox side.
            let record = MailboxRecord::new(key, value, expires.unwrap_or(9000u64));
            let request_id = network.put_record_mailbox(record, Some(mail_id));

            if request_id.is_ok() {
                // Block until the connection is closed again due to expires.
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

// Get a record from the kademlia DHT
fn get_record(matches: &ArgMatches) -> QueryResult<()> {
    if let Some(matches) = matches.subcommand_matches("get-record") {
        if let Some(Matches {
            mail_id,
            mail_addr,
            key,
            ..
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();

            // Create behaviour that uses the custom Handler to describe how peers should react to events
            // The P2PNetworkBehaviour implements the SwarmContext trait for sending request and response messages and using the kademlia DHT
            let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public())?;
            // Create a network that implements the behaviour in it's swarm, and manages mailboxes and connections.
            let mut network = P2PNetwork::new(behaviour, local_keys, None)?;
            println!("Local PeerId: {:?}", network.local_peer_id());

            // Connect to a remote mailbox on the server.
            network.add_mailbox(mail_id, mail_addr)?;

            // Search for a record in the kademlia DHT.
            // The search is successful if a known peer has published a record and it is not expired.
            // Triggers the Handler's handle_kademlia_event() function.
            network.swarm.get_record(key);
            // Block until the connection is closed again due to expires.
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

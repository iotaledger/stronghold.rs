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

use crate::mailbox_protocol::{MailboxCodec, MailboxProtocol, MailboxRecord, MailboxRequest};
use crate::network_behaviour::P2PNetworkBehaviour;
use async_std::{
    io::{stdin, BufReader},
    task,
};
use futures::{future, prelude::*};
use libp2p::{
    build_development_transport,
    core::Multiaddr,
    identity::Keypair,
    kad::{record::store::MemoryStore, record::Key, Kademlia, Quorum},
    mdns::Mdns,
    request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig},
    swarm::{ExpandedSwarm, IntoProtocolsHandler, NetworkBehaviour, ProtocolsHandler},
    PeerId, Swarm,
};
use regex::Regex;
use std::{
    error::Error,
    iter,
    str::FromStr,
    string::String,
    task::{Context, Poll},
};

mod structs_proto {
    include!(concat!(env!("OUT_DIR"), "/structs.pb.rs"));
}
mod mailbox_protocol;
mod network_behaviour;

type P2PNetworkSwarm = ExpandedSwarm<
    P2PNetworkBehaviour,
    <<<P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent,
    <<<P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::OutEvent,
    <P2PNetworkBehaviour as NetworkBehaviour>::ProtocolsHandler,
    PeerId,
>;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a random PeerId
    let local_keys = Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_keys.public());
    println!("Local peer id: {:?}", local_peer_id);

    // create a transport
    let transport = build_development_transport(local_keys)?;

    // Create a Kademlia behaviour.
    let kademlia = {
        let store = MemoryStore::new(local_peer_id.clone());
        Kademlia::new(local_peer_id.clone(), store)
    };
    let mdns = Mdns::new()?;

    // Create RequestResponse behaviour with MailboxProtocol
    let msg_proto = {
        // set request_timeout and connection_keep_alive if necessary
        let cfg = RequestResponseConfig::default();
        let protocols = iter::once((MailboxProtocol(), ProtocolSupport::Full));
        RequestResponse::new(MailboxCodec(), protocols, cfg)
    };
    // Create a Swarm that establishes connections through the given transport
    // Use custom behaviour P2PNetworkBehaviour
    let mut swarm = {
        let behaviour = P2PNetworkBehaviour {
            kademlia,
            mdns,
            msg_proto,
        };
        Swarm::new(transport, behaviour, local_peer_id)
    };

    // Set specific port
    if let Some(i) = std::env::args().position(|arg| arg == "--port") {
        let port = std::env::args().nth(i + 1).unwrap_or_else(|| String::from("16384"));
        let addr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        Swarm::listen_on(&mut swarm, addr)?;
    } else {
        Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/16384".parse()?)?;
    }

    let mailbox_peer = attempt_connect_mailbox(&mut swarm);

    poll_input(swarm, mailbox_peer)
}

fn attempt_connect_mailbox(swarm: &mut P2PNetworkSwarm) -> Option<PeerId> {
    std::env::args().position(|arg| arg == "--mailbox").and_then(|index| {
        if let Some(addr) = std::env::args()
            .nth(index + 1)
            .and_then(|addr_arg| Multiaddr::from_str(&*addr_arg).ok())
            .and_then(|addr| Swarm::dial_addr(swarm, addr.clone()).ok().map(|_| addr))
        {
            println!("Dialed mailbox{}.", addr);
            if let Some(peer_id) = std::env::args()
                .nth(index + 2)
                .and_then(|peer_arg| PeerId::from_str(&*peer_arg).ok())
            {
                swarm.kademlia.add_address(&peer_id, addr);
                if swarm.kademlia.bootstrap().is_ok() {
                    println!("Successful bootstrapping.");
                } else {
                    eprintln!("Could not bootstrap.");
                }
                return Some(peer_id);
            }
        } else {
            eprintln!("Missing or invalid remote multi-address.");
        }
        None
    })
}

fn poll_input(mut swarm: P2PNetworkSwarm, mailbox_peer: Option<PeerId>) -> Result<(), Box<dyn Error>> {
    let mut stdin = BufReader::new(stdin()).lines();
    let mut listening = false;
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        loop {
            // poll for user input in stdin
            match stdin.try_poll_next_unpin(cx)? {
                Poll::Ready(Some(line)) => handle_input_line(&mut swarm, line, mailbox_peer.as_ref()),
                Poll::Ready(None) => panic!("Stdin closed"),
                Poll::Pending => break,
            }
        }
        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("{:?}", event),
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    if !listening {
                        for a in Swarm::listeners(&swarm) {
                            println!("Listening on {:?}", a);
                        }
                        listening = true;
                        println!("Type LIST to view current kademlia bucket entries");
                        println!("Type PING \"<peer_id>\" to ping another peer");
                        if mailbox_peer.is_some() {
                            println!("Type GET \"<key>\" to fetch a record");
                            println!("Type PUT \"<key>\" \"<value>\" <timeout_sec:OPTIONAL> to put a record into the mailbox");
                        }
                    }
                    break;
                }
            }
        }
        Poll::Pending
    }))
}

fn handle_input_line(swarm: &mut P2PNetworkSwarm, line: String, mailbox_peer: Option<&PeerId>) {
    if let Some(command) = Regex::new(r"(PING|GET|PUT|LIST)")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .map(|cap_match| cap_match.as_str())
    {
        match command {
            "PING" => send_ping_to_peer(line, &mut swarm.msg_proto),
            "GET" => fetch_record(line, &mut swarm.kademlia),
            "PUT" => publish_record(line, &mut swarm.msg_proto, mailbox_peer),
            "LIST" => {
                println!("Current Buckets:");
                for bucket in swarm.kademlia.kbuckets() {
                    for entry in bucket.iter() {
                        println!("key: {:?}, values: {:?}", entry.node.key.preimage(), entry.node.value);
                    }
                }
            }
            _ => eprintln!("Invalid command."),
        }
    } else {
        eprintln!("Invalid command.");
    }
}

fn send_ping_to_peer(line: String, msg_proto: &mut RequestResponse<MailboxCodec>) {
    if let Some(peer_id) = Regex::new("PING\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
    {
        let ping = MailboxRequest::Ping;
        println!("Sending Ping to peer {:?}", peer_id);
        msg_proto.send_request(&peer_id, ping);
    } else {
        eprintln!("Missing or invalid target peer id.");
    }
}

fn publish_record(line: String, msg_proto: &mut RequestResponse<MailboxCodec>, mailbox_peer: Option<&PeerId>) {
    if let Some(cap) = Regex::new("PUT\\s+\"([\\w\\-_\\.]+)\"\\s*\"(.+)\"\\s*(\\d+)?")
        .ok()
        .and_then(|regex| regex.captures(&line))
    {
        let key = String::from(cap.get(1).unwrap().as_str());
        let value = String::from(cap.get(2).unwrap().as_str());
        let timeout_sec = cap
            .get(3)
            .and_then(|t_match| t_match.as_str().parse::<u64>().ok())
            .unwrap_or(0u64);
        let record = MailboxRecord {
            key,
            value,
            timeout_sec,
        };
        if let Some(peer) = mailbox_peer {
            println!(
                "Sending publish request for record {:?}:{:?} to peer: {:?}",
                record.key, record.value, peer
            );
            msg_proto.send_request(peer, MailboxRequest::Publish(record));
        } else {
            eprintln!("Missing mailbox peer.");
        }
    } else {
        eprintln!("Missing or invalid input.");
    }
}

fn fetch_record(line: String, kademlia: &mut Kademlia<MemoryStore>) {
    if let Some(key_match) = Regex::new("GET\\s+\"([\\w\\-_\\.]+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
    {
        let key = Key::new(&key_match.as_str());
        kademlia.get_record(&key, Quorum::One);
    } else {
        eprintln!("Missing key.");
    }
}

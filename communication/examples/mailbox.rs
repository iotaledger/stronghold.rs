// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example implements the mailbox behaviour. It can be used to communicate with remote peers in different networks
//! that can not be dialed directly, e.g. because they are not listening to a public IP address.
//! Records for remote peers are sent to the mailbox that stores them.
//! The remote peer can then connect to the same mailbox and query it for the record.
//! This example is only a PoC for the mailbox-concept and doesn't implement any security measure yet.
//!
//! In order for it to work, the peer that serves as a mailbox has to obtain a public IP e.g. by running on
//! a server or by configuring port forwarding.
//!
//! # Starting the mailbox
//!
//! The mailbox can run either with the provided `Dockerfile`, or directly from the command line. Per default, the
//! mailbox runs on port 16384, if multiple mailboxes should run on the same device the port has to be configured to be
//! different.
//! ```sh
//! mailbox-start-mailbox
//! Start a mailbox that publishes records in kademlia upon receiving them in a request
//!
//! USAGE:
//!     mailbox start-mailbox [OPTIONS]
//!
//! OPTIONS:
//!     -p, --port <listening-port>    the listening port for the peer, default is 16384
//! ```
//! ```sh
//! $ cargo run --example mailbox -- start-mailbox
//! Local PeerId: PeerId("12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG")
//! Local PeerId: PeerId("12D3KooWF3V2hx6kCQr4WZ3Z1TvLQLEJixxqzBNhdo59B7PZ6Gzm")
//! Listening on "/ip4/127.0.0.1/tcp/16384"
//! Listening on "/ip4/192.168.178.32/tcp/16384"
//! Listening on "/ip4/172.17.0.1/tcp/16384"
//! Listening on "/ip6/::1/tcp/16384"
//! ```
//! # Deposit a record in the mailbox
//!
//! ```sh
//! mailbox-put-mailbox
//! Put record into the mailbox
//!
//! USAGE:
//!     mailbox put_mailbox [OPTIONS] --mail-addr <mailbox-multi-addr> --key <record-key> --value <record-value>
//!
//! OPTIONS:
//!     -k, --key <record-key>                  the key for the record
//!     -a, --mail-addr <mailbox-multi-addr>    the multiaddr of the mailbox
//!     -v, --value <record-value>              the value for the record
//! ```
//!
//! Using the above mailbox, a record can be deposited this mailbox could be done by running:
//!
//! ```sh
//! $ cargo run --example mailbox -- put-mailbox -a "/ip4/127.0.0.1/tcp/16384" -k "foo" -v "bar"
//! Outcome(Success)
//! ```
//!
//! # Reading a record
//!
//! ```sh
//! mailbox-get-record
//! Get record from local or the mailbox
//!
//! USAGE:
//!     mailbox get-record --mail-addr <mailbox-multi-addr> --key <record-key>
//!
//! OPTIONS:
//!     -k, --key <record-key>                  the key for the record
//!     -a, --mail-addr <mailbox-multi-addr>    the multi-address of the mailbox
//! ```
//!
//! Using the above mailbox, a record is read from the mailbox by running
//!
//! ```sh
//! $ cargo run --example mailbox -- get-record -a "/ip4/127.0.0.1/tcp/16384" -k "foo"
//! "foo":
//! "bar"
//! ```

use async_std::task;
use clap::{load_yaml, App, ArgMatches};
use core::{ops::Deref, str::FromStr};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stronghold_communication::{
    behaviour::{P2PEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::{ConnectedPoint, Keypair, Multiaddr, Swarm, SwarmEvent},
};

pub type Key = String;
pub type Value = String;

/// Indicates if a Request was received and / or the associated operation at the remote peer was successful
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestOutcome {
    Success,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxRecord {
    key: String,
    value: String,
}

impl MailboxRecord {
    pub fn new(key: Key, value: Key) -> Self {
        MailboxRecord { key, value }
    }

    pub fn key(&self) -> Key {
        self.key.clone()
    }
    pub fn value(&self) -> Value {
        self.value.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    PutRecord(MailboxRecord),
    GetRecord(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Outcome(RequestOutcome),
    Record(MailboxRecord),
}

// only used for this CLI
struct Matches {
    mail_addr: Multiaddr,
    key: String,
    value: Option<String>,
}

// Match and parse the arguments from the command line
fn eval_arg_matches(matches: &ArgMatches) -> Option<Matches> {
    if let Some(mail_addr) = matches
        .value_of("mailbox_addr")
        .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
    {
        if let Some(key) = matches.value_of("key").map(|k| k.to_string()) {
            let value = matches.value_of("value").map(|v| v.to_string());
            return Some(Matches { mail_addr, key, value });
        }
    }
    None
}

// Start a mailbox that publishes record for other peers
fn run_mailbox(matches: &ArgMatches) {
    if matches.subcommand_matches("start-mailbox").is_some() {
        let local_keys = Keypair::generate_ed25519();

        // Create swarm for communication
        let mut swarm =
            P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys).expect("Could not create swarm.");
        Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/16384".parse().unwrap()).expect("Listening error.");
        println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));
        // temporary key-value store
        let mut local_records = BTreeMap::new();
        // Poll for events from the swarm
        task::block_on(async {
            loop {
                match swarm.next_event().await {
                    SwarmEvent::NewListenAddr(addr) => {
                        println!("Listening on {:?}", addr);
                    }
                    SwarmEvent::ListenerError { error } => {
                        println!("Listener error: {:?}", error);
                        return;
                    }
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(event)) => {
                        // Handle messages from remote peers
                        if let P2PReqResEvent::Req {
                            peer_id: _,
                            request_id,
                            request,
                        } = event.deref().clone()
                        {
                            match request {
                                // Store the record as a key-value pair in the local binary
                                // tree
                                Request::PutRecord(record) => {
                                    local_records.insert(record.key(), record.value());
                                    swarm
                                        .send_response(Response::Outcome(RequestOutcome::Success), request_id)
                                        .unwrap();
                                }
                                // Send the record for that key to the remote peer
                                Request::GetRecord(key) => {
                                    if let Some((key, value)) = local_records.get_key_value(&key) {
                                        let record = MailboxRecord::new(key.clone(), value.clone());
                                        swarm.send_response(Response::Record(record), request_id).unwrap();
                                    } else {
                                        swarm
                                            .send_response(Response::Outcome(RequestOutcome::Error), request_id)
                                            .unwrap();
                                    }
                                }
                            };
                        }
                    }
                    _ => {}
                }
            }
        });
    }
}

// Deposit a record in the mailbox
fn put_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("put-mailbox") {
        if let Some(Matches {
            mail_addr,
            key,
            value: Some(value),
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();
            // Create swarm for communication
            let mut swarm =
                P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys).expect("Could not create swarm.");

            // Connect to a remote mailbox on the server and then send the request.
            Swarm::dial_addr(&mut swarm, mail_addr.clone()).unwrap();
            loop {
                match task::block_on(swarm.next_event()) {
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                        let event = boxed_event.deref().clone();
                        if let P2PReqResEvent::Res {
                            peer_id: _,
                            request_id: _,
                            response,
                        } = event
                        {
                            println!("{:?}", response);
                        } else {
                            println!("{:?}", event);
                        }
                        return;
                    }
                    // Send the request once a conncection was successful
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint: ConnectedPoint::Dialer { address },
                        num_established: _,
                    } => {
                        if address == mail_addr {
                            let record = MailboxRecord::new(key.clone(), value.clone());
                            swarm.send_request(&peer_id, Request::PutRecord(record));
                        }
                    }
                    SwarmEvent::UnknownPeerUnreachableAddr { address, error: _ } => {
                        if address == mail_addr {
                            println!("Could not dial address {:?}", address);
                            return;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
}

// Get a record from the mailbox
fn get_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("get-record") {
        if let Some(Matches { mail_addr, key, .. }) = eval_arg_matches(matches) {
            let local_keys = Keypair::generate_ed25519();

            // Create swarm for communication
            let mut swarm =
                P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys).expect("Could not create swarm.");

            // Connect to a remote mailbox on the server and then send the request.
            Swarm::dial_addr(&mut swarm, mail_addr.clone()).unwrap();
            loop {
                match task::block_on(swarm.next_event()) {
                    SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                        if let P2PReqResEvent::Res {
                            peer_id: _,
                            request_id: _,
                            response: Response::Record(record),
                        } = boxed_event.deref().clone()
                        {
                            println!("{:?}:\n{:?}", record.key(), record.value());
                        } else {
                            println!("{:?}", boxed_event.deref().clone());
                        }
                        return;
                    }
                    // Send the request once a conncection was successful
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint: ConnectedPoint::Dialer { address },
                        num_established: _,
                    } => {
                        if address == mail_addr {
                            swarm.send_request(&peer_id, Request::GetRecord(key.clone()));
                        }
                    }
                    SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                        if address == mail_addr {
                            println!("Could not dial address {:?}: {:?}", address, error);
                            return;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    run_mailbox(&matches);
    put_record(&matches);
    get_record(&matches);
}

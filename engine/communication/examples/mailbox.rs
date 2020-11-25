// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example implements the mailbox behaviour. It can be used to communicate with remote peers in different networks
//! that can not be dialed directly, e.g. because they are not listening to a public IP address.
//! Records for remote peers are sent to the mailbox that stores them.
//! The remote peer can then connect to the same mailbox and query it for the record.
//!
//! In order for this example to work, the peer that serves as a mailbox has to obtain a public IP e.g. by running on
//! a server or by configuring port forwarding.
//!
//! # Starting the mailbox
//! ```sh
//! $ cargo run --example mailbox -- start-mailbox
//! Local PeerId: PeerId("12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG")
//! Listening on:
//! "/ip4/127.0.0.1/tcp/16384"
//! "/ip4/192.168.178.25/tcp/16384"
//! "/ip4/172.17.0.1/tcp/16384"
//! "/ip6/::1/tcp/16384"
//! ```
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
//!     -k, --key <record-key>                  the key for the record
//!     -a, --mail-addr <mailbox-multi-addr>    the multiaddr of the mailbox
//!     -i, --mail-id <mailbox-peer-id>         the peer id of the mailbox
//!     -v, --value <record-value>              the value for the record
//! ```
//!
//! Using the above mailbox, a record can be deposited this mailbox could be done by running:
//!
//! ```sh
//! $ cargo run --example mailbox -- put-mailbox  -i "12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG" -a "/ip4/127.0.0.1/tcp/16384" -k "foo" -v "bar"
//! Local PeerId: PeerId("12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA")
//! Received Result for publish request RequestId(1): Success.
//! ```
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
//! $ cargo run --example mailbox -- get-record  -i "12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG" -a "/ip4/127.0.0.1/tcp/16384" -k "foo"
//! Local PeerId: PeerId("12D3KooWJjtPjcMMa19WTnYvsmgpagPnDjSjeTgZS7j3YhwZX7Gn")
//! Got record "foo" "bar".
//! ```

use async_std::task;
use clap::{load_yaml, App, ArgMatches};
use communication::{
    behaviour::P2PNetworkBehaviour,
    error::QueryResult,
    message::{CommunicationEvent, MailboxRecord, ReqResEvent, Request, RequestOutcome, Response},
};
use core::{
    str::FromStr,
    task::{Context, Poll},
};
use futures::{future, prelude::*};
use libp2p::{
    core::{identity::Keypair, PeerId},
    multiaddr::Multiaddr,
    swarm::Swarm,
};
use std::collections::BTreeMap;

// only used for this CLI
struct Matches {
    mail_id: PeerId,
    mail_addr: Multiaddr,
    key: String,
    value: Option<String>,
}

// Match and parse the arguments from the command line
fn eval_arg_matches(matches: &ArgMatches) -> Option<Matches> {
    if let Some(mail_id) = matches
        .value_of("mailbox_id")
        .and_then(|id_arg| PeerId::from_str(&id_arg).ok())
    {
        if let Some(mail_addr) = matches
            .value_of("mailbox_addr")
            .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
        {
            if let Some(key) = matches.value_of("key").map(|k| k.to_string()) {
                let value = matches.value_of("value").map(|v| v.to_string());
                return Some(Matches {
                    mail_id,
                    mail_addr,
                    key,
                    value,
                });
            }
        }
    }
    None
}

// Start a mailbox that publishes record for other peers
fn run_mailbox(matches: &ArgMatches) -> QueryResult<()> {
    if matches.subcommand_matches("start-mailbox").is_some() {
        let local_keys = Keypair::generate_ed25519();

        // Create swarm for communication
        let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
        P2PNetworkBehaviour::start_listening(&mut swarm, Some("/ip4/0.0.0.0/tcp/16384".parse().unwrap()))?;
        println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));
        let mut listening = false;
        let mut local_records = BTreeMap::new();
        task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
            // poll for events from the swarm, store incoming key-value-records and answer request for
            // keys
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    if let CommunicationEvent::RequestResponse {
                        peer_id: _,
                        request_id,
                        event: ReqResEvent::Req(request),
                    } = event
                    {
                        println!("Request:{:?}", request);
                        match request {
                            Request::Ping => {
                                swarm.send_response(Response::Pong, request_id).unwrap();
                            }
                            Request::PutRecord(record) => {
                                local_records.insert(record.key(), record.value());
                                swarm
                                    .send_response(Response::Outcome(RequestOutcome::Success), request_id)
                                    .unwrap();
                            }
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
                Poll::Ready(None) => {
                    return Poll::Ready(());
                }
                Poll::Pending => {
                    if !listening {
                        let mut listeners = Swarm::listeners(&swarm).peekable();
                        if listeners.peek() == None {
                            println!("No listeners. The port may already be occupied.")
                        } else {
                            println!("Listening on:");
                            for a in listeners {
                                println!("{:?}", a);
                            }
                        }

                        listening = true;
                    }
                }
            }
            Poll::Pending
        }));
    }
    Ok(())
}

// Deposit a record in the mailbox
fn put_record(matches: &ArgMatches) -> QueryResult<()> {
    if let Some(matches) = matches.subcommand_matches("put-mailbox") {
        if let Some(Matches {
            mail_id,
            mail_addr,
            key,
            value: Some(value),
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();
            // Create swarm for communication
            let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
            println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));

            // Connect to a remote mailbox on the server.
            swarm.add_peer(mail_id.clone(), mail_addr.clone());

            let mut original_id = None;
            // Block until the response is received
            task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
                // poll for the outcome of the request
                match swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => {
                        if let CommunicationEvent::RequestResponse {
                            peer_id: _,
                            request_id,
                            event: ReqResEvent::Res(response),
                        } = event
                        {
                            println!("Response:{:?}", response);
                            if original_id.is_some() && request_id == original_id.clone().unwrap() {
                                println!("Response from Mailbox: {:?}", response);
                                return Poll::Ready(());
                            }
                        }
                        Poll::Pending
                    }
                    Poll::Ready(None) => Poll::Ready(()),
                    Poll::Pending => {
                        if original_id.is_none() {
                            if Swarm::connection_info(&mut swarm, &mail_id).is_none()
                                && Swarm::dial_addr(&mut swarm, mail_addr.clone()).is_err()
                            {
                                println!("Could not dial addr");
                                return Poll::Ready(());
                            }
                            // Deposit a record on the mailbox
                            let record = MailboxRecord::new(key.clone(), value.clone());
                            original_id = Some(swarm.send_request(mail_id.clone(), Request::PutRecord(record)));
                            println!("Send Put Record Request {:?}", original_id.clone());
                        }
                        Poll::Pending
                    }
                }
            }));
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
    Ok(())
}

// Get a record from the mailbox
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

            // Create swarm for communication
            let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
            println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));

            let mut original_id = None;
            // Block until the response was received.
            task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
                // poll for the outcome of the request
                match swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => {
                        if let CommunicationEvent::RequestResponse {
                            peer_id: _,
                            request_id,
                            event: ReqResEvent::Res(response),
                        } = event
                        {
                            println!("Response:{:?}", response);
                            if original_id.is_some() && request_id == original_id.clone().unwrap() {
                                if let Response::Record(record) = response {
                                    println!("Key:\n{:?}, Value:\n{:?}", record.key(), record.value());
                                } else {
                                    println!("Response from Mailbox: {:?}", response);
                                }
                                return Poll::Ready(());
                            }
                        }
                        Poll::Pending
                    }
                    Poll::Ready(None) => Poll::Ready(()),
                    Poll::Pending => {
                        if original_id.is_none() {
                            // Connect to a remote mailbox on the server.
                            swarm.add_peer(mail_id.clone(), mail_addr.clone());
                            if Swarm::connection_info(&mut swarm, &mail_id).is_none()
                                && Swarm::dial_addr(&mut swarm, mail_addr.clone()).is_err()
                            {
                                println!("Could not dial addr");
                                return Poll::Ready(());
                            }

                            // Get Record from remote peer
                            original_id = Some(swarm.send_request(mail_id.clone(), Request::GetRecord(key.clone())));
                            println!("Send Get Record Request {:?}", original_id);
                        }
                        Poll::Pending
                    }
                }
            }));
        } else {
            eprintln!("Invalid or missing arguments");
        }
    }
    Ok(())
}

fn main() -> QueryResult<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    run_mailbox(&matches)?;
    put_record(&matches)?;
    get_record(&matches)?;
    Ok(())
}

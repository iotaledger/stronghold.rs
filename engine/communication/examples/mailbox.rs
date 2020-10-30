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
//! "/ip4/127.0.0.1/tcp/41807"
//! "/ip4/192.168.178.25/tcp/41807"
//! "/ip4/172.17.0.1/tcp/41807"
//! "/ip6/::1/tcp/41807"
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
//! $ cargo run --example mailbox -- put-mailbox  -i "12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG" -a "/ip4/127.0.0.1/tcp/16384" -k "foo" -v "bar"
//! Local PeerId: PeerId("12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA")
//! Received Result for publish request RequestId(1): Success.
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
//! $ cargo run --example mailbox -- get-record  -i "12D3KooWLVFib1KbfjY4Qv3phtc8hafD8HVJm9QygeSmH28Jw2HG" -a "/ip4/127.0.0.1/tcp/16384" -k "foo"
//! Local PeerId: PeerId("12D3KooWJjtPjcMMa19WTnYvsmgpagPnDjSjeTgZS7j3YhwZX7Gn")
//! Got record "foo" "bar".
//! ```

use async_std::task;
use clap::{load_yaml, App, ArgMatches};
use communication::{
    behaviour::{P2PNetworkBehaviour, SwarmContext},
    error::QueryResult,
    message::{MailboxRecord, Request},
};
use core::{
    str::FromStr,
    task::{Context, Poll},
};
use futures::{future, prelude::*};
use libp2p::{
    core::{identity::Keypair, PeerId},
    multiaddr::{multiaddr, Multiaddr},
    swarm::{Swarm, SwarmEvent},
};

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

// Start a mailbox that publishes record for other peers
fn run_mailbox(matches: &ArgMatches) -> QueryResult<()> {
    if matches.subcommand_matches("start-mailbox").is_some() {
        let local_keys = Keypair::generate_ed25519();

        // Create swarm for communication
        let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
        let port = matches
            .value_of("port")
            .and_then(|port_str| port_str.parse::<u16>().ok())
            .unwrap_or(16384u16);
        P2PNetworkBehaviour::start_listening(&mut swarm, Some(multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port))))?;
        println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));
        let mut listening = false;
        task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
            loop {
                // poll for events from the swarm
                match swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => println!("{:?}", event),
                    Poll::Ready(None) => {
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        if !listening {
                            let mut listeners = P2PNetworkBehaviour::get_listeners(&mut swarm).peekable();
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
                        break;
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
            expires,
        }) = eval_arg_matches(matches)
        {
            let local_keys = Keypair::generate_ed25519();
            // Create swarm for communication
            let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
            println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));

            // Connect to a remote mailbox on the server.
            swarm.add_peer(mail_id.clone(), mail_addr);

            // Deposit a record on the mailbox
            // Triggers the Handler's handle_request_msg() Request::Publish(r) on the mailbox side.
            let record = MailboxRecord::new(key, value, expires.unwrap_or(9000u64));
            swarm.send_request(&mail_id, Request::PutRecord(record));
            // Block until the connection is closed again due to expires.
            task::block_on(async move {
                loop {
                    if let SwarmEvent::ConnectionClosed { .. } = swarm.next_event().await {
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

            // Connect to a remote mailbox on the server.
            swarm.add_peer(mail_id.clone(), mail_addr);

            // Get Record from remote peer
            swarm.send_request(&mail_id, Request::GetRecord(key));
            // Block until the connection is closed again due to expires.
            task::block_on(async move {
                loop {
                    if let SwarmEvent::ConnectionClosed { .. } = swarm.next_event().await {
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

fn main() -> QueryResult<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    run_mailbox(&matches)?;
    put_record(&matches)?;
    get_record(&matches)?;
    Ok(())
}

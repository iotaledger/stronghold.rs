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

//! A basic application for communication between peers in the same local network.
//!
//! Start the peers in different terminal windows. If the local network allows mDNS, they will automatically connect.
//!
//! ```sh
//! cargo run --example local-echo
//! ```
//! For each peer it will print its unique PeerId and the listening addresses within the local network.
//! ```sh
//! Local PeerId: PeerId("12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA")
//! Listening on:
//! "/ip4/127.0.0.1/tcp/41807"
//! "/ip4/192.168.178.25/tcp/41807"
//! "/ip4/172.17.0.1/tcp/41807"
//! "/ip6/::1/tcp/41807"
//! ```
//!
//! The following commands are available for communication and could be used by another peer to communicate
//! with the first one by pinging it `PING` or sending a message `MSG`:
//!
//! ```sh
//! PING "12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA"
//! MSG "12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA" "The answer to life, the universe and everything is 42."
//! ```
//!
//! Upon receiving a message, the peer will send an echo of the same message back to the original peer.
//!
//! # Connecting peers manually
//!
//! The connected peers can be listed with their listening addr with the command
//! ```sh
//! LIST
//! ```
//!
//! If the peers are within the same network but other peers is not listed, it can manually added with one
//! of its listening address:
//! ```sh
//! DIAL "/ip4/127.0.0.1/tcp/41807"
//! ```

use async_std::{
    io::{stdin, BufReader, Stdin},
    task,
};
use communication::{
    behaviour::{P2PNetworkBehaviour, P2PNetworkSwarm, SwarmContext},
    error::QueryResult,
    message::{CommunicationEvent, Request},
};
use core::{
    str::FromStr,
    task::{Context, Poll},
};
use std::{error::Error, string::String};

use futures::{future, io::Lines, prelude::*};
use libp2p::{
    core::{identity::Keypair, Multiaddr, PeerId},
    swarm::Swarm,
};
use regex::Regex;

// Poll for user input
fn poll_stdin(stdin: &mut Lines<BufReader<Stdin>>, cx: &mut Context<'_>) -> Result<Option<String>, Box<dyn Error>> {
    loop {
        match stdin.try_poll_next_unpin(cx)? {
            Poll::Ready(Some(line)) => {
                return Ok(Some(line));
            }
            Poll::Ready(None) => panic!("Stdin closed"),
            Poll::Pending => return Ok(None),
        }
    }
}

fn listen() -> QueryResult<()> {
    let local_keys = Keypair::generate_ed25519();

    // Create a Swarm that implementes the Request-Reponse Protocl and mDNS
    let mut swarm = P2PNetworkBehaviour::new(local_keys)?;
    P2PNetworkBehaviour::start_listening(&mut swarm, None)?;
    println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));
    let mut listening = false;
    let mut stdin = BufReader::new(stdin()).lines();
    // Start polling for user input and events in the network
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        if let Ok(Some(line)) = poll_stdin(&mut stdin, cx) {
            if !line.is_empty() {
                handle_input_line(&mut swarm, line)
            }
        }
        loop {
            // poll for events from the swarm
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    if let CommunicationEvent::RequestMessage {
                        originating_peer,
                        id: _,
                        procedure,
                    } = event
                    {
                        println!("Received message from peer {:?}\n{:?}", originating_peer, procedure);
                    }
                }
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
                        println!("commands:");
                        println!("PING <peer_id>");
                        println!("DIAL <peer_addr>");
                        if cfg!(feature = "mdns") {
                            println!("LIST");
                        } else {
                            println!("Since mdns is not enabled, peers have to be DIALed first to connect before PING / MSG them");
                        }
                        listening = true;
                    }
                    break;
                }
            }
        }
        Poll::Pending
    }));
    Ok(())
}

fn handle_input_line(swarm: &mut P2PNetworkSwarm, line: String) {
    if let Some(peer_id) = Regex::new("PING\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
    {
        swarm.send_request(&peer_id, Request::Ping);
        println!("Pinged {:?}", peer_id);
    } else if cfg!(feature = "mdns") && line.contains("LIST") {
        #[cfg(feature = "mdns")]
        {
            let known_peers = swarm.get_active_mdns_peers();
            for peer in &known_peers {
                println!("{:?}", peer);
            }
        }
    }
    if let Some(peer_addr) = Regex::new("DIAL\\s+\"(/\\w+/.+/tcp/\\d+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| Multiaddr::from_str(peer_match.as_str()).ok())
    {
        if P2PNetworkSwarm::dial_addr(swarm, peer_addr.clone()).is_ok() {
            println!("Dialed {:?}", peer_addr);
        };
    } else {
        eprintln!("Missing or invalid arguments");
    }
}

fn main() -> QueryResult<()> {
    listen()
}

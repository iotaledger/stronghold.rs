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
//!Listening on:
//!"/ip4/127.0.0.1/tcp/41807"
//!"/ip4/192.168.178.25/tcp/41807"
//!"/ip4/172.17.0.1/tcp/41807"
//!"/ip6/::1/tcp/41807"
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
//!

use async_std::{
    io::{stdin, BufReader, Stdin},
    task,
};
use communication::{
    behaviour::{InboundEventCodec, P2PNetworkBehaviour, SwarmContext},
    error::QueryResult,
    message::{Request, Response},
    network::P2PNetwork,
};
use core::{
    str::FromStr,
    task::{Context, Poll},
};
use std::{error::Error, string::String};

use futures::{future, io::Lines, prelude::*};
#[cfg(feature = "kademlia")]
use libp2p::kad::KademliaEvent;
use libp2p::{
    core::{identity::Keypair, Multiaddr, PeerId},
    request_response::{RequestId, ResponseChannel},
};
use regex::Regex;

struct Handler();

// Implement a Handler to determine the networks behaviour upon receiving messages.
// This example does make use of libp2ps Kademlia.
impl InboundEventCodec for Handler {
    fn handle_request_msg(
        swarm: &mut impl SwarmContext,
        request: Request,
        channel: ResponseChannel<Response>,
        peer: PeerId,
    ) {
        match request {
            Request::Ping => {
                println!("Received Ping from {:?}. Sending a Pong back.", peer);
                swarm.send_response(Response::Pong, channel);
            }
            Request::Message(msg) => {
                println!("Received Message from {:?}:\n{:?}\nSending an echo back.", peer, msg);
                swarm.send_response(Response::Message("echo: ".to_string() + &msg), channel);
            }
            Request::Publish(_) => {}
        }
    }

    fn handle_response_msg(_swarm: &mut impl SwarmContext, response: Response, request_id: RequestId, peer: PeerId) {
        match response {
            Response::Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            Response::Result(result) => {
                println!("Received Result for request {:?}: {:?}.", request_id, result);
            }
            Response::Message(msg) => {
                println!("Received Response from peer {:?}:\n{:?}.", peer, msg);
            }
        }
    }

    #[cfg(feature = "kademlia")]
    fn handle_kademlia_event(_swarm: &mut impl SwarmContext, _result: KademliaEvent) {}
}

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

    // Create behaviour that uses the custom handler to describe how peers should react to events
    // The P2PNetworkBehaviour implements the SwarmContext trait for sending request and response messages and using the kademlia DHT
    let behaviour = P2PNetworkBehaviour::<Handler>::new(local_keys.public())?;
    // Create a network that implements the behaviour in its swarm, and manages mailboxes and connections.
    let mut network = P2PNetwork::new(behaviour, local_keys, None)?;
    println!("Local PeerId: {:?}", network.local_peer_id());

    let mut listening = false;
    let mut stdin = BufReader::new(stdin()).lines();
    // Start polling for user input and events in the network
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        if let Ok(Some(line)) = poll_stdin(&mut stdin, cx) {
            if !line.is_empty() {
                handle_input_line(&mut network, line)
            }
        }
        loop {
            // poll for events from the swarm
            match network.swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("{:?}", event),
                Poll::Ready(None) => {
                    return Poll::Ready(());
                }
                Poll::Pending => {
                    if !listening {
                        network.print_listeners();
                        println!("commands:");
                        println!("PING <peer_id>");
                        println!("DIAL <peer_addr>");
                        println!("MSG <peer_id> <message>");
                        println!("LIST");
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

fn handle_input_line(network: &mut P2PNetwork<Handler>, line: String) {
    if let Some((peer_id, message)) = Regex::new("MSG\\s+\"(\\w+)\"\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1).and_then(|p| cap.get(2).map(|m| (p, m))))
        .and_then(|(peer_match, msg)| {
            PeerId::from_str(peer_match.as_str())
                .ok()
                .map(|p| (p, msg.as_str().to_string()))
        })
    {
        let req = Request::Message(message);
        network.swarm.send_request(&peer_id, req);
    } else if let Some(peer_id) = Regex::new("PING\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
    {
        network.swarm.send_request(&peer_id, Request::Ping);
    } else if line.contains("LIST") {
        network.swarm.print_known_peers();
    } else if let Some(peer_addr) = Regex::new("DIAL\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| Multiaddr::from_str(peer_match.as_str()).ok())
    {
        if network.dial_addr(peer_addr.clone()).is_ok() {
            println!("Dialed {:?}", peer_addr);
        };
    } else {
        eprintln!("Missing or invalid arguments");
    }
}

fn main() -> QueryResult<()> {
    listen()
}

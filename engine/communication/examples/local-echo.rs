// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
//! The ping command is available to test the connection to another peers:
//!
//! ```sh
//! PING "12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA"
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
use communication::behaviour::{
    error::QueryResult,
    message::{CommunicationEvent, P2PIdentifyEvent, P2PReqResEvent},
    P2PNetworkBehaviour,
};
use core::{
    ops::Deref,
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
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Msg(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Msg(String),
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
    // Create a Swarm that implementes the Request-Reponse Protocl and mDNS
    let mut swarm = P2PNetworkBehaviour::<Request, Response>::new(local_keys)?;
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
                Poll::Ready(Some(e)) => match e {
                    CommunicationEvent::RequestResponse(event) => match event.deref().clone() {
                        P2PReqResEvent::Req {
                            peer_id,
                            request_id,
                            request,
                        } => {
                            println!("Received message from peer {:?}\n{:?}", peer_id, request);
                            match request {
                                Request::Ping => {
                                    let response = swarm.send_response(Response::Pong, request_id);
                                    if response.is_ok() {
                                        println!("Send Pong back");
                                    } else {
                                        println!("Error sending pong: {:?}", response.unwrap_err());
                                    }
                                }
                                Request::Msg(msg) => {
                                    let response =
                                        swarm.send_response(Response::Msg(format!("echo: {}", msg)), request_id);
                                    if response.is_ok() {
                                        println!("Echoed message");
                                    } else {
                                        println!("Error sending echo: {:?}", response.unwrap_err());
                                    }
                                }
                            }
                        }
                        P2PReqResEvent::Res {
                            peer_id,
                            request_id,
                            response,
                        } => println!(
                            "Response from peer {:?} for Request {:?}:\n{:?}",
                            peer_id, request_id, response
                        ),
                        error => {
                            println!("Error {:?}", error)
                        }
                    },
                    CommunicationEvent::Identify(event) => {
                        if let P2PIdentifyEvent::Received {
                            peer_id,
                            info: _,
                            observed_addr,
                        } = event.deref().clone()
                        {
                            println!(
                                "Received identify event: {:?} observes us at {:?}",
                                peer_id, observed_addr
                            );
                        }
                    }
                    _ => {}
                },
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
                        println!("commands:");
                        println!("PING <peer_id>");
                        println!("MSG <peer_id>");
                        println!("DIAL <peer_addr>");
                        println!("LIST");
                        if cfg!(not(feature = "mdns")) {
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

fn handle_input_line(swarm: &mut Swarm<P2PNetworkBehaviour<Request, Response>>, line: String) {
    if let Some(peer_id) = Regex::new("PING\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
    {
        swarm.send_request(&peer_id, Request::Ping);
        println!("Pinged {:?}", peer_id);
    } else if let Some((peer_id, msg)) = Regex::new("MSG\\s+\"(\\w+)\"\\s+\"(\\w+)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1).and_then(|p| cap.get(2).map(|m| (p, m))))
        .and_then(|(peer_match, msg)| {
            PeerId::from_str(peer_match.as_str())
                .ok()
                .map(|p| (p, msg.as_str().to_string()))
        })
    {
        swarm.send_request(&peer_id, Request::Msg(msg.clone()));
        println!("Send msg {:?} to peer {:?}", msg, peer_id);
    } else if line.contains("LIST") {
        println!("Known peers:");
        let known_peers = swarm.get_all_peers();
        for (peer, addr) in known_peers {
            println!("{:?}: {:?}", peer, addr);
        }
    } else if let Some(peer_addr) = Regex::new("DIAL\\s+\"(/\\w+/.+/tcp/\\d+(:?/\\w+)*)\"")
        .ok()
        .and_then(|regex| regex.captures(&line))
        .and_then(|cap| cap.get(1))
        .and_then(|peer_match| Multiaddr::from_str(peer_match.as_str()).ok())
    {
        if Swarm::dial_addr(swarm, peer_addr.clone()).is_ok() {
            println!("Dialed {:?}", peer_addr);
        };
    } else {
        eprintln!("Missing or invalid arguments");
    }
}

fn main() -> QueryResult<()> {
    listen()
}

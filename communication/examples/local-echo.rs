// Copyright 2020-2021 IOTA Stiftung
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
//! Listen on: "/ip4/127.0.0.1/tcp/41807"
//! Listen on: "/ip4/192.168.178.25/tcp/41807"
//! Listen on: "/ip4/172.17.0.1/tcp/41807"
//! Listen on: "/ip6/::1/tcp/41807"
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
    io::{stdin, BufReader},
    task,
};
use communication::{
    behaviour::{BehaviourConfig, P2PEvent, P2PIdentifyEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::{Keypair, Multiaddr, PeerId, Swarm, SwarmEvent},
};
use core::{ops::Deref, str::FromStr};
use futures::{prelude::*, select};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Msg(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Msg(String),
}

// Parse the user input line and handle the commands
fn handle_input_line(swarm: &mut Swarm<P2PNetworkBehaviour<Request, Response>>, line: &str) {
    let target_regex = "(?:\\s+\"(?P<target>[[:alnum:]]{32,64}?)\")?";
    let msg_regex = "(?:\\s+\"(?P<msg>[^\"]+)\")?";
    let regex = "(?P<type>LIST|DIAL|PING|MSG)".to_string() + target_regex + msg_regex;
    if let Some(captures) = Regex::new(&regex).expect("Invalid Reqex string.").captures(&line) {
        match captures
            .name("type")
            .expect("No capture for match name 'type'.")
            .as_str()
        {
            "LIST" => {
                println!("Known peers:");
                for peer in swarm.behaviour().get_all_peers() {
                    println!("{:?}", peer);
                }
            }
            "DIAL" => {
                // Dial a multiaddress to establish a connection, if this was successful the identify protocol will
                // cause the two peers to send `P2PEvent::Identify` events to each other.
                if let Some(peer_addr) = captures
                    .name("target")
                    .and_then(|peer_match| Multiaddr::from_str(peer_match.as_str()).ok())
                {
                    if swarm.dial_addr(peer_addr.clone()).is_ok() {
                        println!("Dialed {:?}", peer_addr);
                    }
                } else {
                    eprintln!("Missing or invalid address");
                }
            }
            "PING" => {
                // Pings a peer by it's peer address, this will only be successful if the peer is
                // known to the local peer either my mDNS or by previously dialing it.
                if let Some(peer_id) = captures
                    .name("target")
                    .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
                {
                    swarm.behaviour_mut().send_request(&peer_id, Request::Ping);
                    println!("Pinged {:?}", peer_id);
                } else {
                    eprintln!("Missing or invalid peer id");
                }
            }
            "MSG" => {
                // Messages a peer by its peer address, this will only be successful if the peer is
                // known to the local peer either my mDNS or by previously dialing it.
                if let Some(peer_id) = captures
                    .name("target")
                    .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
                {
                    if let Some(msg) = captures.name("msg").map(|msg_match| msg_match.as_str().to_string()) {
                        swarm.behaviour_mut().send_request(&peer_id, Request::Msg(msg.clone()));
                        println!("Send msg {:?} to peer {:?}", msg, peer_id);
                        return;
                    }
                }
                eprintln!("Missing arguments or invalid peer id");
            }
            _ => {}
        }
    } else {
        eprintln!("Invalid arguments");
    }
}

// Handle an event that was polled from the swarm.
// These events are either messages from remote peers or events from the protocols i.g.
// `P2PEvent::Identify`
fn handle_event(swarm: &mut Swarm<P2PNetworkBehaviour<Request, Response>>, e: P2PEvent<Request, Response>) {
    match e {
        P2PEvent::RequestResponse(event) => match event.deref().clone() {
            // Request from a remote peer
            P2PReqResEvent::Req {
                peer_id,
                request_id,
                request,
            } => {
                println!("Received message from peer {:?}\n{:?}", peer_id, request);
                match request {
                    Request::Ping => {
                        let response = swarm.behaviour_mut().send_response(&request_id, Response::Pong);
                        if response.is_ok() {
                            println!("Send Pong back");
                        } else {
                            println!("Error sending pong: {:?}", response.unwrap_err());
                        }
                    }
                    Request::Msg(msg) => {
                        let response = swarm
                            .behaviour_mut()
                            .send_response(&request_id, Response::Msg(format!("echo: {}", msg)));
                        if response.is_ok() {
                            println!("Echoed message");
                        } else {
                            println!("Error sending echo: {:?}", response.unwrap_err());
                        }
                    }
                }
            }
            // Response to an request that out local peer send before
            P2PReqResEvent::Res {
                peer_id,
                request_id,
                response,
            } => println!(
                "Response from peer {:?} for Request {:?}:\n{:?}\n",
                peer_id, request_id, response
            ),
            P2PReqResEvent::ResSent { .. } => {}
            error => {
                println!("Error {:?}", error)
            }
        },
        // Identify event that is send by the identify-protocol once two peer establish a
        // connection
        P2PEvent::Identify(event) => {
            if let P2PIdentifyEvent::Received { peer_id, info } = event.deref().clone() {
                println!(
                    "Received identify event: {:?} observes us at {:?}\n",
                    peer_id, info.observed_addr
                );
            }
        }
        _ => {}
    }
}

// Create a swarm and poll for events from that swarm
async fn listen() {
    let local_keys = Keypair::generate_ed25519();
    let config = BehaviourConfig::default();

    // Create a Swarm that implementes the Request-Reponse-, Identify-, and mDNS-Protocol
    let mut swarm = P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config)
        .await
        .expect("Could not create swarm.");
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Invalid Multiaddress."))
        .expect("Listening Error.");

    println!(
        "Local PeerId: {:?}\ncommands:\nPING <peer_id>\nMSG <peer_id>\nDIAL <peer_addr>\nLIST",
        swarm.local_peer_id()
    );
    if cfg!(not(feature = "mdns")) {
        println!("Since mdns is not enabled, peers have to be DIALed first to connect before PING / MSG them");
    }

    let mut stdin = BufReader::new(stdin()).lines();
    // Start polling for user input and events in the network
    loop {
        select! {
            // User input from stdin
            stdin_input = stdin.next().fuse()=> {
                if let Some(Ok(command)) = stdin_input {
                    handle_input_line(&mut swarm, &command);
                } else {
                    // stdin closed
                    break;
                }
            },
            // Events from the swarm
            swarm_event = swarm.next_event().fuse() => {
                match swarm_event {
                    SwarmEvent::Behaviour(event) => handle_event(&mut swarm, event),
                    SwarmEvent::NewListenAddr(addr) => println!("Listen on {:?}", addr),
                    SwarmEvent::ListenerError{error} => {
                        eprintln!("ListenerError: {:?}", error);
                        return;
                    },
                    _ => {},
                }
            },
        };
    }
}

fn main() {
    task::block_on(listen())
}

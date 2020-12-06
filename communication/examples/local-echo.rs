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
    io::{stdin, BufReader},
    task,
};
use core::{
    ops::Deref,
    str::FromStr,
    task::{Context, Poll},
};
use stronghold_communication::behaviour::{
    error::{QueryError, QueryResult},
    message::{P2PEvent, P2PIdentifyEvent, P2PReqResEvent},
    P2PNetworkBehaviour,
};

use futures::{future, prelude::*};
use libp2p::{
    core::{identity::Keypair, Multiaddr, PeerId},
    swarm::Swarm,
};
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

fn handle_input_line(swarm: &mut Swarm<P2PNetworkBehaviour<Request, Response>>, line: &str) {
    let target_regex = "(?:\\s+\"(?P<target>[^\"]+)\")?";
    let msg_regex = "(?:\\s+\"(?P<msg>[^\"]+)\")?";
    let regex = "(?P<type>LIST|DIAL|PING|MSG)".to_string() + target_regex + msg_regex;
    if let Some(captures) = Regex::new(&regex).unwrap().captures(&line) {
        match captures.name("type").unwrap().as_str() {
            "LIST" => {
                println!("Known peers:");
                let known_peers = swarm.get_all_peers();
                for (peer, addr) in known_peers {
                    println!("{:?}: {:?}", peer, addr);
                }
            }
            "DIAL" => {
                if let Some(peer_addr) = captures
                    .name("target")
                    .and_then(|peer_match| Multiaddr::from_str(peer_match.as_str()).ok())
                {
                    if Swarm::dial_addr(swarm, peer_addr.clone()).is_ok() {
                        println!("Dialed {:?}", peer_addr);
                    }
                } else {
                    eprintln!("Missing or invalid address");
                }
            }
            "PING" => {
                if let Some(peer_id) = captures
                    .name("target")
                    .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
                {
                    swarm.send_request(&peer_id, Request::Ping);
                    println!("Pinged {:?}", peer_id);
                } else {
                    eprintln!("Missing or invalid peer id");
                }
            }
            "MSG" => {
                if let Some(peer_id) = captures
                    .name("target")
                    .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
                {
                    if let Some(msg) = captures.name("msg").map(|msg_match| msg_match.as_str().to_string()) {
                        swarm.send_request(&peer_id, Request::Msg(msg.clone()));
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

fn handle_event(swarm: &mut Swarm<P2PNetworkBehaviour<Request, Response>>, e: P2PEvent<Request, Response>) {
    match e {
        P2PEvent::RequestResponse(event) => match event.deref().clone() {
            P2PReqResEvent::Req {
                peer_id,
                request_id: Some(request_id),
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
                        let response = swarm.send_response(Response::Msg(format!("echo: {}", msg)), request_id);
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
        P2PEvent::Identify(event) => {
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
    }
}

fn listen() -> QueryResult<()> {
    let local_keys = Keypair::generate_ed25519();
    // Create a Swarm that implementes the Request-Reponse Protocl and mDNS
    let mut swarm = P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys)?;
    if let Err(err) = Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse().unwrap()) {
        return Err(QueryError::ConnectionError(format!("{}", err)));
    }
    println!("Local PeerId: {:?}", Swarm::local_peer_id(&swarm));
    let mut listening = false;
    let mut stdin = BufReader::new(stdin()).lines();
    // Start polling for user input and events in the network
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        loop {
            match stdin.poll_next_unpin(cx) {
                Poll::Ready(Some(line)) => handle_input_line(&mut swarm, &line.unwrap()),
                Poll::Ready(None) => panic!("Stdin closed"),
                Poll::Pending => {}
            }
            // poll for events from the swarm
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(e)) => handle_event(&mut swarm, e),
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
                }
            }
        }
    }));
    Ok(())
}

fn main() -> QueryResult<()> {
    listen()
}

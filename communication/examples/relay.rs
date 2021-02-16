// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_std::{
    io::{stdin, BufReader},
    task,
};
use clap::{load_yaml, App, ArgMatches};
use core::{ops::Deref, str::FromStr, time::Duration};
use futures::{prelude::*, select};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Instant};
use stronghold_communication::{
    behaviour::{BehaviourConfig, P2PEvent, P2PNetworkBehaviour, P2PReqResEvent, RequestEnvelope},
    libp2p::{ConnectedPoint, Keypair, Multiaddr, PeerId, Swarm, SwarmEvent},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ack;

// Start a mailbox that publishes record for other peers
fn run_relay(matches: &ArgMatches) {
    if matches.subcommand_matches("start-relay").is_some() {
        let local_keys = Keypair::generate_ed25519();
        let config = BehaviourConfig::new(Some(Duration::from_secs(5)), Some(Duration::from_secs(60)));
        // Create swarm for communication
        let mut swarm = P2PNetworkBehaviour::<RequestEnvelope<String>, Ack>::init_swarm(local_keys, config)
            .expect("Could not create swarm.");
        Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/16384".parse().unwrap()).expect("Listening error.");
        println!("\nLocal PeerId: {:?}", Swarm::local_peer_id(&swarm));

        // map request from original peer to the request send to target
        let mut requests = HashMap::new();

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
                        match event.deref().clone() {
                            // forward incoming request to the targeted peer
                            P2PReqResEvent::Req {
                                peer_id,
                                request_id,
                                request,
                            } => {
                                // verify that the claimed source is the actual peer that send the request
                                if peer_id.to_string() != request.source {
                                    continue;
                                }

                                // forward request to the target
                                if let Ok(target) = PeerId::from_str(&request.target) {
                                    let forward_request = swarm.send_request(&target, request);
                                    requests.insert(forward_request, request_id);
                                }
                            }
                            P2PReqResEvent::Res {
                                peer_id: _,
                                request_id,
                                response,
                            } => {
                                if let Some(original_request) = requests.remove(&request_id) {
                                    let _ = swarm.send_response(original_request, response);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        });
    }
}

fn start_peer(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("connect") {
        let relay_addr = matches
            .value_of("relay_addr")
            .and_then(|addr_arg| Multiaddr::from_str(addr_arg).ok())
            .expect("Missing or invalid relay address");
        let local_keys = Keypair::generate_ed25519();

        // Create swarm for communication
        let config = BehaviourConfig::new(Some(Duration::from_secs(10)), Some(Duration::from_secs(60)));
        let mut swarm = P2PNetworkBehaviour::<RequestEnvelope<String>, Ack>::init_swarm(local_keys, config)
            .expect("Could not create swarm.");
        println!("\nLocal Peer Id {:?}", Swarm::local_peer_id(&swarm));

        Swarm::dial_addr(&mut swarm, relay_addr.clone()).expect("Could not dial address.");

        let start = Instant::now();
        let relay_peer = task::block_on(async {
            loop {
                let event = swarm.next_event().await;
                match event {
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint: ConnectedPoint::Dialer { address },
                        num_established: _,
                    } => {
                        if address == relay_addr {
                            return Some(peer_id);
                        }
                    }
                    SwarmEvent::UnreachableAddr {
                        peer_id: _,
                        address,
                        error,
                        attempts_remaining: 0,
                    }
                    | SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                        println!("Could not connect address {:?}: {:?}", address, error);
                        return None;
                    }
                    _ => {}
                }
                if start.elapsed() > Duration::new(3, 0) {
                    return None;
                }
            }
        })
        .expect("Could not connect relay");

        println!("\n'SET \"<targe-peer-id>\"' to set the target for your messages.");

        let mut stdin = BufReader::new(stdin()).lines();
        // Start polling for user input and events in the network
        task::block_on(async {
            let mut peer_target: Option<PeerId> = None;
            loop {
                select! {
                    // User input from stdin
                    stdin_input = stdin.next().fuse()=> {
                        if let Some(Ok(command)) = stdin_input {
                            handle_input_line(&mut swarm, &command, relay_peer, &mut peer_target);
                        } else {
                            // stdin closed
                            break;
                        }
                    },
                    // Events from the swarm
                    event = swarm.next().fuse() => handle_event(&mut swarm, event, relay_peer, &mut peer_target),
                };
            }
        });
    }
}

// Handle an event that was polled from the swarm.
// These events are either messages from remote peers or events from the protocols i.g.
// `P2PEvent::Identify`
fn handle_event(
    swarm: &mut Swarm<P2PNetworkBehaviour<RequestEnvelope<String>, Ack>>,
    e: P2PEvent<RequestEnvelope<String>, Ack>,
    relay_peer: PeerId,
    remote_target: &mut Option<PeerId>,
) {
    if let P2PEvent::RequestResponse(event) = e {
        match event.deref().clone() {
            // Request from a remote peer
            P2PReqResEvent::Req {
                peer_id,
                request_id,
                request:
                    RequestEnvelope {
                        source,
                        message,
                        target,
                    },
            } => {
                if target != Swarm::local_peer_id(&swarm).to_string() {
                    return;
                }
                if source != peer_id.to_string() && peer_id != relay_peer {
                    return;
                }
                if remote_target.is_some() && remote_target.unwrap().to_string() == source {
                    println!("> {:?}", message);
                } else if let Ok(source) = PeerId::from_str(&source) {
                    println!("\n==== Message from {:?}\n\n>{:?}", source, message);
                    remote_target.replace(source);
                }
                swarm.send_response(request_id, Ack).expect("Failed to send ack back.")
            }
            // Response to an request that out local peer send before
            P2PReqResEvent::Res {
                peer_id: _,
                request_id: _,
                response: _,
            }
            | P2PReqResEvent::ResSent {
                peer_id: _,
                request_id: _,
            } => {}
            error => println!("Error {:?}", error),
        }
    }
}

fn handle_input_line(
    swarm: &mut Swarm<P2PNetworkBehaviour<RequestEnvelope<String>, Ack>>,
    line: &str,
    relay_peer: PeerId,
    remote_target: &mut Option<PeerId>,
) {
    let regex = Regex::new("SET\\s+\"(?P<target>[^\"]+)\"").unwrap();
    if let Some(captures) = regex.captures(&line) {
        if let Some(peer_id) = captures
            .name("target")
            .and_then(|peer_match| PeerId::from_str(peer_match.as_str()).ok())
        {
            remote_target.replace(peer_id);
            println!("\n==== Success, start typing to send messages.\n");
        } else {
            eprintln!("Missing arguments or invalid peer id");
        }
    } else if let Some(remote) = remote_target {
        let request = RequestEnvelope {
            source: Swarm::local_peer_id(swarm).to_string(),
            message: line.to_string(),
            target: remote.to_string(),
        };
        swarm.send_request(&relay_peer, request);
    } else {
        eprintln!("Invalid arguments or not know remote peer");
    }
}

fn main() {
    let yaml = load_yaml!("cli_relay.yml");
    let matches = App::from(yaml).get_matches();
    run_relay(&matches);
    start_peer(&matches);
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example demonstrates a dynamic usage of the Stronghold-P2p firewall.
//! Instead setting fixed rules, it dynamically asks the user to set a firewall rule for each peer that connects.
//!
//! There are two different types of requests we can send to a remote:
//! - Ping: `-p <remote-peer-id>` -> A Pong will automatically be sent back as response
//! - Message `-p <remote-peer-id> -m <message>` -> Remote has 20s time to type a response message.
//!
//! Per default no rule is set for inbound requests.
//! When a Alice then would like to send a request to Bob for the first time, Bob is prompted to set
//! a general firewall rule for requests from Alice. The following options are provided
//! - yes: Permit all requests from Alice
//! - no: Reject all requests from Alice
//! - ping: Only allow type _Ping_, but not _Message_.
//! - ask: Ask for individual approval for each request
//! In case of ask, Bob will be prompted for each request, including the current one, to manually approve or
//! reject.
//!
//! To test this example, run it in two terminal windows T1 & T2.
//! It will each print the peer id of the local peer, which can be used to reach this peer.
//! T1:
//! ```sh
//! Local Peer Id: 12D3KooWRgJG7no2snYqGM8jwABTs952KFb6GHghzz1vRw7T5Cmd
//! ```
//! T2:
//! ```sh
//! Local Peer Id: 12D3KooWG364edSdRCv5LG5adzsAdE3vafYqc5rGHCYpvT7dmHPa
//! ```
//!
//! Because mDNS is enabled in this example, peers aromatically learn the listening addresses of other peers
//! in the same network, that is used to dial this peer.
//!
//!
//! In T1 run
//! ```sh
//! -p 12D3KooWG364edSdRCv5LG5adzsAdE3vafYqc5rGHCYpvT7dmHPa -m "test message"
//! ```
//! the id being the one that was printed in T2.
//!
//! In the second terminal, it will ask for the firewall rule:
//! T2:
//! ```sh
//! Peer 12D3KooWRgJG7no2snYqGM8jwABTs952KFb6GHghzz1vRw7T5Cmd connected. Allow requests from them?: (yes/no/ask/ping)
//! > ask
//!
//! # Ask for individual approval due to rule "Ask"
//! Received Request with type Message from peer 12D3KooWRgJG7no2snYqGM8jwABTs952KFb6GHghzz1vRw7T5Cmd. Permit?: (yes/no)
//! > yes
//!
//! # The actual message is shown
//! Received Message from peer 12D3KooWRgJG7no2snYqGM8jwABTs952KFb6GHghzz1vRw7T5Cmd:
//! "test message".
//! > test response
//! ```
//!
//! The response will then be printed in T1:
//! ```sh
//! Response: test response
//! ```
//! Note: While waiting for a response T1 is blocking.

use futures::{channel::mpsc, FutureExt, StreamExt};
use p2p::{
    firewall::{
        permissions::{FirewallPermission, PermissionValue, RequestPermissions, VariantPermission},
        FirewallRequest, FirewallRules, FwRequest, Rule,
    },
    ChannelSinkConfig, EventChannel, PeerId, ReceiveRequest, StrongholdP2p,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{error::Error, str::FromStr, sync::Arc, time::Duration};
use tokio::io::{stdin, AsyncBufReadExt, BufReader, Lines, Stdin};

const RETRY_USER_INPUT_MAX: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
enum Request {
    Ping,
    Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Response {
    Pong,
    Message(String),
}

// Permit only messages of type "Ping". See `p2p::firewall:permissions` module for more info.
fn allow_only_ping(request: &RequestPermission) -> bool {
    let allowed_variant = FirewallPermission::none().add_permissions([&RequestPermission::Ping.permission()]);
    allowed_variant.permits(&request.permission())
}

// Handle user input through stdin.
// Expect either of:
// - "-p <peer-id>": Send a ping
// - "-p <peer-id> -m <message>"": Send a message
async fn on_user_input(
    network: &mut StrongholdP2p<Request, Response, RequestPermission>,
    input: String,
) -> Result<(), Box<dyn Error>> {
    let peer_regex = "-p\\s+(?P<target>[[:alnum:]]{32,64})";
    let peer: PeerId = match Regex::new(peer_regex).expect("Valid regex.").captures(&input) {
        Some(capture) => {
            let target = capture
                .name("target")
                .expect("Regex should only match strings with a 'target' capture group.");
            match PeerId::from_str(target.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    println!("Invalid Peer Id");
                    return Ok(());
                }
            }
        }
        None => {
            println!("Please include a target via \"-p <peer-id>\"");
            return Ok(());
        }
    };
    let type_regex = "-m (?P<msg>\"[^\"]*\"|\\S+)";
    let request = match Regex::new(type_regex).expect("Valid regex.").captures(&input) {
        Some(capture) => {
            let msg = capture
                .name("msg")
                .expect("Regex should only match strings with a 'msg' capture group.")
                .as_str();
            Request::Message(msg.into())
        }
        None => Request::Ping,
    };
    // Send request and wait for response
    match network.send_request(peer, request).await {
        Ok(res) => match res {
            Response::Pong => println!("Pong"),
            Response::Message(msg) => println!("Response: {}", msg),
        },
        Err(e) => println!("Request failed: {}", e),
    }
    Ok(())
}

// Handle an approved inbound request.
async fn on_inbound_request(
    stdin: &mut Lines<BufReader<Stdin>>,
    request: ReceiveRequest<Request, Response>,
) -> Result<(), Box<dyn Error>> {
    let ReceiveRequest {
        peer,
        request,
        response_tx,
        ..
    } = request;
    match request {
        Request::Ping => {
            println!("Received Ping from peer {}.", peer);
            // Send Pong back.
            match response_tx.send(Response::Pong) {
                Ok(()) => println!("Sent Pong back."),
                Err(_) => println!("Sending Pong back failed."),
            }
        }
        Request::Message(msg) => {
            println!("Received Message from peer {}:\n{}.", peer, msg);
            futures::select_biased! {
                stdin_input = stdin.next_line().fuse() => {
                    let line = stdin_input?.unwrap_or_default();
                    // Send response message back.
                    match response_tx.send(Response::Message(line)) {
                        Ok(()) => println!("Sent message back."),
                        Err(_) => println!("Sending message back failed.")
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(20)).fuse() => {
                    println!("Timeout sending a response.");
                }
            }
        }
    }
    Ok(())
}

// Handle a request from the firewall to ask for rules or individual approval.
async fn on_firewall_request(
    stdin: &mut Lines<BufReader<Stdin>>,
    request: FirewallRequest<RequestPermission>,
) -> Result<(), Box<dyn Error>> {
    match request {
        // Ask for rules that should be set for inbound requests from this peer.
        FirewallRequest::PeerSpecificRule { peer, rule_tx } => {
            println!("Peer {} connected. Allow requests from them?: (yes/no/ask/ping)", peer);
            let mut tries = 0;
            loop {
                // Return rule through `rule_tx` oneshot channel.
                // This rule will now apply for all inbound requests from this peer.
                match stdin.next_line().await?.unwrap().as_str() {
                    "yes" => break rule_tx.send(Rule::AllowAll).unwrap(),
                    "no" => break rule_tx.send(Rule::RejectAll).unwrap(),
                    "ask" => break rule_tx.send(Rule::Ask).unwrap(),
                    "ping" => {
                        // Create rule that only permits ping-messages.
                        let rule: Rule<RequestPermission> = Rule::Restricted {
                            restriction: Arc::new(allow_only_ping),
                            // _maker: PhantomData,
                        };
                        rule_tx.send(rule).unwrap();
                        break;
                    }
                    _ => {
                        tries += 1;
                        if tries < RETRY_USER_INPUT_MAX {
                            println!("Invalid input. Please enter one of the following: yes/no/ask/ping")
                        } else {
                            println!("Invalid input. Aborting.");
                            break;
                        }
                    }
                }
            }
        }
        // Ask for individual approval of a request because `Rule::Ask` has been set
        FirewallRequest::RequestApproval {
            peer,
            request,
            approval_tx,
        } => {
            println!(
                "Received Request with type {:?} from peer {}. Permit?: (yes/no)",
                request, peer
            );
            let mut tries = 0;
            loop {
                // Return response through `approval_tx` oneshot channel.
                match stdin.next_line().await?.unwrap().as_str() {
                    "yes" => break approval_tx.send(true).unwrap(),
                    "no" => break approval_tx.send(false).unwrap(),
                    _ => {
                        tries += 1;
                        if tries < RETRY_USER_INPUT_MAX {
                            println!("Invalid input. Please enter one of the following: yes/no")
                        } else {
                            println!("Invalid input. Aborting.");
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Channel for rule- / approval- requests from the firewall.
    let (firewall_tx, mut firewall_rx) = mpsc::channel(10);
    // Channel through which approved inbound requests are forwarded.
    let (request_tx, mut request_rx) = EventChannel::new(10, ChannelSinkConfig::Block);

    let mut rules = FirewallRules::default();
    rules.set_default(Some(Rule::AllowAll));
    let mut network = StrongholdP2p::new(firewall_tx, request_tx, None, rules).await?;

    network.start_listening("/ip4/0.0.0.0/tcp/0".parse()?).await?;
    println!("\nLocal Peer Id: {}", network.peer_id());

    println!("\nPing or message a remote peer:\n`-p <peer-id>`\t\t\t# Send a ping\n`-p <peer-id> -m <message>`\t# Send a message\n");

    let mut stdin = BufReader::new(stdin()).lines();
    loop {
        futures::select! {
            stdin_input = stdin.next_line().fuse() => match stdin_input? {
                Some(line) => on_user_input(&mut network, line).await?,
                None => break,
            },
            request = request_rx.select_next_some() => {
                on_inbound_request(&mut stdin, request).await?;
            }
            request = firewall_rx.select_next_some() => {
                on_firewall_request(&mut stdin, request).await?;
            }
        }
    }
    Ok(())
}

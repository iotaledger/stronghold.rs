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

use async_std::{
    io::{stdin, BufReader, Stdin},
    task,
};
use communication::{
    behaviour::{
        codec::{Codec, CodecContext},
        P2PNetworkBehaviour,
    },
    error::QueryResult,
    message::{Request, Response},
    network::P2PNetwork,
};
use std::{
    error::Error,
    str::FromStr,
    string::String,
    task::{Context, Poll},
};

use futures::{future, io::Lines, prelude::*};
#[cfg(feature = "kademlia")]
use libp2p::kad::KademliaEvent;
use libp2p::{
    core::{identity::Keypair, PeerId},
    request_response::{RequestId, ResponseChannel},
};
use regex::Regex;

struct Handler();

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

impl Codec for Handler {
    fn handle_request_msg(ctx: &mut impl CodecContext, request: Request, channel: ResponseChannel<Response>) {
        match request {
            Request::Ping => {
                println!("Received Ping, we will send a Pong back.");
                ctx.send_response(Response::Pong, channel);
            }
            Request::Message(msg) => {
                println!("Received Message {:?}.\nType a response or enter for no response", msg);
            }
            _ => {}
        }
    }

    fn handle_response_msg(_ctx: &mut impl CodecContext, response: Response, request_id: RequestId) {
        match response {
            Response::Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            #[cfg(feature = "kademlia")]
            Response::Result(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
            _ => {}
        }
    }
    #[cfg(feature = "kademlia")]
    fn handle_kademlia_event(_ctx: &mut impl CodecContext, _result: KademliaEvent) {}
}

fn listen() -> QueryResult<()> {
    let local_keys = Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_keys.public());
    let new_network = P2PNetworkBehaviour::new(local_peer_id, Handler())
        .and_then(|behaviour| P2PNetwork::new(behaviour, local_keys, None));
    if let Ok(mut network) = new_network {
        let mut listening = false;
        let mut stdin = BufReader::new(stdin()).lines();
        task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
            if let Ok(Some(line)) = poll_stdin(&mut stdin, cx) {
                if !line.is_empty() {
                    handle_input_line(&mut network, line)
                }
            }
            loop {
                match network.swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => println!("{:?}", event),
                    Poll::Ready(None) => {
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        if !listening {
                            network.print_listeners();
                            println!("commands:");
                            println!("MSG <peer_id> to message another peer");
                            println!("LIST to view list of known peers");
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
    } else if line.contains("LIST") {
        network.swarm.print_known_peers();
    } else {
        eprintln!("Missing or invalid arguments");
    }
}

fn main() -> QueryResult<()> {
    listen()
}

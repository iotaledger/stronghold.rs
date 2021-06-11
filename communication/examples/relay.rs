//! Copyright 2020-2021 IOTA Stiftung
//! SPDX-License-Identifier: Apache-2.0
//!
//! Stronghold Relay Server Example
//!
//!

use clap::Clap;
use communication::{
    behaviour::{BehaviourConfig, P2PEvent, P2PNetworkBehaviour, P2PReqResEvent},
    libp2p::Keypair,
};
use futures::executor::block_on;
use libp2p::Multiaddr;
use log::*;
use serde::{Deserialize, Serialize};
use std::{error::Error, time::Duration};

#[derive(Clap)]
#[clap(name = "Relay server")]
struct RelayApp {
    #[clap(long, short = 'm', about = "Multiaddr for relay server")]
    multiaddr: Multiaddr,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {}

fn start_relay(r: RelayApp) -> Result<(), Box<dyn Error>> {
    let local_keys = Keypair::generate_ed25519();
    let config = BehaviourConfig::new(
        None,
        None,
        Some(Duration::from_millis(500)),
        Some(Duration::from_millis(500)),
    );

    let mut swarm = block_on(P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config))?;
    swarm.listen_on(r.multiaddr)?;

    block_on(async {
        loop {
            match swarm.next().await {
                P2PEvent::RequestResponse(v) => match *v {
                    P2PReqResEvent::Req {
                        request,
                        peer_id,
                        request_id,
                    } => {}
                    P2PReqResEvent::Res {
                        response,
                        peer_id,
                        request_id,
                    } => {}
                    P2PReqResEvent::ResSent { peer_id, request_id } => {}
                    P2PReqResEvent::InboundFailure {
                        error,
                        peer_id,
                        request_id,
                    } => {}
                    P2PReqResEvent::OutboundFailure {
                        error,
                        peer_id,
                        request_id,
                    } => {}
                    _ => {}
                },
                _ => {}
            }
        }
    });

    Ok(())
}

fn main() {
    let relay_app = RelayApp::parse();

    if let Err(e) = start_relay(relay_app) {
        error!("Failed to start relay server")
    }
}

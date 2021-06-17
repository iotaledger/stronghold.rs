// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stronghold Relay Server Example
//!
//! This example simply spawns a relay server to relay traffic between
//! multiple clients.
//!
//! run with
//! ```no_run
//! cargo run --example relay -- --multiaddr "/ip4/0.0.0.0/tcp/7001"
//! ```

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
        // Set idle connection timeout high so that the relay doesn't actively closes a connection.
        // Instead source / destination peer should disconnect when not using the relay anymore.
        Some(Duration::from_secs(3600)),
    );

    let addr = r.multiaddr;
    info!("Starting relay server. Listening on: {}", addr);

    let mut swarm = block_on(P2PNetworkBehaviour::<Request, Response>::init_swarm(
        local_keys.clone(),
        config,
    ))?;
    swarm.listen_on(addr)?;

    // print local peer_id
    let local_peer_id = local_keys.public().into_peer_id();
    info!(r#"PeerId: "{}""#, local_peer_id.to_base58());

    block_on(async {
        loop {
            if let P2PEvent::RequestResponse(event) = swarm.next().await {
                match *event {
                    P2PReqResEvent::Req { request, peer_id, .. } => {
                        info!("Incoming Request: Request={:?}, PeerId={}", request, peer_id)
                    }
                    P2PReqResEvent::Res { response, peer_id, .. } => {
                        info!("Outgoing Response: Response={:?}, PeerId={}", response, peer_id)
                    }
                    P2PReqResEvent::ResSent { peer_id, request_id } => {
                        info!(
                            "Response To Inbound Request has been send: PeerId={}, RequestId={}",
                            peer_id, request_id
                        )
                    }
                    P2PReqResEvent::InboundFailure {
                        error,
                        peer_id,
                        request_id,
                    } => {
                        error!(
                            "Inbound Failure: Error={:?}, PeerId={}, RequestId={}",
                            error, peer_id, request_id
                        )
                    }
                    P2PReqResEvent::OutboundFailure {
                        error,
                        peer_id,
                        request_id,
                    } => {
                        error!(
                            "Outbound Failure: Error={:?}, PeerId={}, RequestId={}",
                            error, peer_id, request_id
                        )
                    }
                }
            } // end if
        }
    });

    Ok(())
}

fn main() {
    // enable logging
    env_logger::init();

    let relay_app = RelayApp::parse();

    if let Err(e) = start_relay(relay_app) {
        error!("Failed to start relay server. Cause: {}", e)
    }
}

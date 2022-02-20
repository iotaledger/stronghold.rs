// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Communication with a Stronghold server
//!
//! This example provides a basic PoC that shows how stronghold-p2p can be used to communicate with a remote
//! Stronghold server, without a local Stronghold running.
//!
//! We are spawning a new client on each operations, to simulate multiple independent clients that could
//! also run in different systems.
//! In case of multiple operations from a singe application, it is recommended to only setup the network once and re-use
//! the client.
//!
//! Note: because we are also mocking the remote stronghold, we need to use `actix_rt` as runtime. If the remote
//! stronghold would actually run on a different system, the network of the local_client could use a any
//! runtime.

use futures::{
    channel::{mpsc, oneshot},
    FutureExt,
};
use iota_stronghold::Location;
use p2p::{Multiaddr, PeerId};
use std::error::Error;

// Mock remote Stronghold
mod remote_stronghold {
    use super::*;
    use futures::future::pending;
    use iota_stronghold::{
        p2p::{NetworkConfig, Rule},
        Stronghold,
    };

    pub async fn run(address_tx: oneshot::Sender<(PeerId, Multiaddr)>) -> Result<(), Box<dyn Error>> {
        let mut stronghold = Stronghold::init_stronghold_system("client".into(), Vec::new()).await?;
        stronghold.spawn_p2p(NetworkConfig::default(), None).await?;
        stronghold.set_firewall_rule(Rule::AllowAll, Vec::new(), true).await?;
        let addr = stronghold.start_listening(None).await??;
        let peer_id = stronghold.get_swarm_info().await?.local_peer_id;
        address_tx.send((peer_id, addr)).unwrap();
        println!("Started remote Stronghold.");
        let _ = pending::<()>().await;
        Ok(())
    }
}

// Local client that is using the remote Stronghold to generate a key and sign messages.
mod local_client {
    use super::*;
    use iota_stronghold::{
        p2p::{ShRequest, ShResult},
        procedures::{Ed25519Sign, GenerateKey, KeyType},
        Location, RecordHint,
    };
    use p2p::{ChannelSinkConfig, EventChannel, StrongholdP2p};

    async fn setup_network(
        stronghold_id: PeerId,
        stronghold_addr: Multiaddr,
    ) -> Result<StrongholdP2p<ShRequest, ShResult>, Box<dyn Error>> {
        let (firewall_tx, _) = mpsc::channel(0);
        let (request_tx, _) = EventChannel::new(0, ChannelSinkConfig::Block);
        let mut network = StrongholdP2p::new(firewall_tx, request_tx, None).await?;
        // Add address info of remote Stronghold.
        network.add_address(stronghold_id, stronghold_addr).await;
        println!("\nStarted new client.");
        Ok(network)
    }

    // Spawn new peer, connect to remote Stronghold and generate a new Ed25519 keypair.
    pub async fn generate_key(
        stronghold_id: PeerId,
        stronghold_addr: Multiaddr,
        location: Location,
    ) -> Result<(), Box<dyn Error>> {
        let mut network = setup_network(stronghold_id, stronghold_addr).await?;
        println!("Generating new ed25519 keypair at location: {:?}", location);
        let key_hint = RecordHint::new("key").unwrap();
        let generate_key = GenerateKey {
            ty: KeyType::Ed25519,
            output: location,
            hint: key_hint,
        };
        let res = network
            .send_request(stronghold_id, ShRequest::Procedure(generate_key.into()))
            .await?;
        match res {
            ShResult::Proc(res) => {
                res?;
            }
            _ => unreachable!("ShRequest::Procedure always returns ShResult::Proc"),
        }
        Ok(())
    }

    // Spawn new peer, connect to remote Stronghold and use the previously generated keypair to sign a message.
    pub async fn sign_message(
        stronghold_id: PeerId,
        stronghold_addr: Multiaddr,
        location: Location,
        message: String,
    ) -> Result<(), Box<dyn Error>> {
        let mut network = setup_network(stronghold_id, stronghold_addr).await?;
        println!(
            "Signing message {:?} with key stored in location: {:?}",
            message, location
        );
        let msg_bytes: Vec<u8> = message.into();
        let sign_message = Ed25519Sign {
            msg: msg_bytes,
            private_key: location,
        };
        let res = network
            .send_request(stronghold_id, ShRequest::Procedure(sign_message.into()))
            .await?;
        match res {
            ShResult::Proc(res) => {
                let signed: Vec<u8> = res?.pop().unwrap().into();
                println!("Signed message: {:?}", signed);
                Ok(())
            }
            _ => unreachable!("ShRequest::Procedure always returns ShResult::Proc"),
        }
    }
}

async fn run_local(info_rx: oneshot::Receiver<(PeerId, Multiaddr)>) -> Result<(), Box<dyn Error>> {
    let (stronghold_id, stronghold_addr) = info_rx.await.unwrap();
    let key_location = Location::generic("v0", "r0");
    // Write a new key into the remote vault
    local_client::generate_key(stronghold_id, stronghold_addr.clone(), key_location.clone()).await?;
    // Run multiple clients that use the created key to sing a message.
    for i in 0..3 {
        let message = format!("message {}", i);
        local_client::sign_message(stronghold_id, stronghold_addr.clone(), key_location.clone(), message).await?;
    }
    Ok(())
}

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (info_tx, info_rx) = oneshot::channel::<(PeerId, Multiaddr)>();

    futures::select! {
        // Run the local clients
        _ = run_local(info_rx).fuse() => {},
        // Run the remote Stronghold
        _ = remote_stronghold::run(info_tx).fuse() => {}
    }
    Ok(())
}

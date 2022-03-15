// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold server
//!
//! This example provides a basic PoC that shows how stronghold-p2p can be used to communicate with a remote
//! Stronghold server, without a local Stronghold running.
//! In an actual application, the `remote_stronghold` and `local_client` would run on different systems.
//!
//! Note: because we are also mocking the remote stronghold, we need to use `actix_rt` as runtime. If the remote
//! stronghold would actually run on a different system, the local_client could use a any runtime.

use futures::{
    channel::{mpsc, oneshot},
    FutureExt,
};
use iota_stronghold::Location;
use p2p::{Multiaddr, PeerId};
use std::error::Error;

const CLIENT_PATH: &[u8; 6] = b"client";

// Mock remote Stronghold
mod remote_stronghold {
    use super::*;
    use futures::future::pending;
    use iota_stronghold::{
        p2p::{NetworkConfig, Permissions},
        Stronghold,
    };

    pub async fn run(address_tx: oneshot::Sender<(PeerId, Multiaddr)>) -> Result<(), Box<dyn Error>> {
        let mut stronghold = Stronghold::init_stronghold_system(CLIENT_PATH.to_vec(), Vec::new()).await?;
        // Allow all inbound requests. In a real application the access for remote peers should be restricted
        // based on the sender's peer-id.
        stronghold
            .spawn_p2p(NetworkConfig::new(Permissions::allow_all()), None)
            .await?;
        let addr = stronghold.start_listening(None).await??;
        let peer_id = stronghold.get_swarm_info().await?.local_peer_id;
        address_tx.send((peer_id, addr)).unwrap();
        println!("Started remote Stronghold.");
        //
        let _ = pending::<()>().await;
        Ok(())
    }
}

// Local client that is using the remote Stronghold to generate a key and sign messages.
mod local_client {
    use super::*;
    use iota_stronghold::{
        p2p::{secure_messages::Procedures, Request, ShRequest, ShResult},
        procedures::{Ed25519Sign, GenerateKey, KeyType, ProcedureOutput},
        Location, RecordHint,
    };
    use p2p::{firewall::FirewallRules, ChannelSinkConfig, EventChannel, StrongholdP2p};

    pub struct StrongholdStub {
        network: StrongholdP2p<ShRequest, ShResult>,
        remote_stronghold_id: PeerId,
    }

    impl StrongholdStub {
        pub async fn new(
            remote_stronghold_id: PeerId,
            remote_stronghold_addr: Multiaddr,
        ) -> Result<Self, Box<dyn Error>> {
            // Use dummy firewall channel since there will be no inbound requests.
            let (firewall_tx, _) = mpsc::channel(0);
            let (request_tx, _) = EventChannel::new(0, ChannelSinkConfig::Block);
            let mut network = StrongholdP2p::new(firewall_tx, request_tx, None, FirewallRules::allow_none()).await?;
            // Add address info of remote Stronghold.
            network.add_address(remote_stronghold_id, remote_stronghold_addr).await;
            println!("\nStarted new client.");
            Ok(StrongholdStub {
                network,
                remote_stronghold_id,
            })
        }

        /// Generate a new Ed25519 keypair at the remote Stronghold.
        pub async fn generate_key(&mut self, location: Location) -> Result<(), Box<dyn Error>> {
            println!("Generating new ed25519 keypair at location: {:?}.", location);
            let key_hint = RecordHint::new("key").unwrap();
            let generate_key = GenerateKey {
                ty: KeyType::Ed25519,
                output: location,
                hint: key_hint,
            };
            self.exec_proc(generate_key).await.map(|_| ())
        }

        /// Use an existing keypair keypair to sign a message.
        pub async fn sign_message(&mut self, location: Location, message: String) -> Result<Vec<u8>, Box<dyn Error>> {
            println!(
                "\nSigning message {:?} with key stored in location: {:?}.",
                message, location
            );
            let msg_bytes: Vec<u8> = message.into();
            let sign_message = Ed25519Sign {
                msg: msg_bytes,
                private_key: location,
            };
            let signed = self.exec_proc(sign_message).await.map(|signed| signed.into())?;
            println!("Signed message: {:?}", signed);
            Ok(signed)
        }

        async fn exec_proc<P: Into<Procedures>>(&mut self, proc: P) -> Result<ProcedureOutput, Box<dyn Error>> {
            let request = ShRequest {
                client_path: CLIENT_PATH.to_vec(),
                request: Request::Procedures(proc.into()),
            };
            let res = self.network.send_request(self.remote_stronghold_id, request).await?;
            match res {
                ShResult::Proc(Ok(mut outputs)) => Ok(outputs.pop().expect("outputs len == number of procedures")),
                ShResult::Proc(Err(e)) => Err(e.into()),
                _ => unreachable!("ShRequest::Procedure always returns ShResult::Proc"),
            }
        }
    }
}

async fn usecase_sign_messages(info_rx: oneshot::Receiver<(PeerId, Multiaddr)>) -> Result<(), Box<dyn Error>> {
    let (stronghold_id, stronghold_addr) = info_rx.await.unwrap();
    let mut remote_stronghold = local_client::StrongholdStub::new(stronghold_id, stronghold_addr).await?;

    let key_location = Location::generic("v0", "r0");
    remote_stronghold.generate_key(key_location.clone()).await?;
    // Use the created key to sing multiple message.
    for i in 0..3 {
        let message = format!("message {}", i);
        remote_stronghold.sign_message(key_location.clone(), message).await?;
    }
    Ok(())
}

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (info_tx, info_rx) = oneshot::channel::<(PeerId, Multiaddr)>();

    futures::select! {
        // Run the local client
        _ = usecase_sign_messages(info_rx).fuse() => {},
        // Run the remote Stronghold
        _ = remote_stronghold::run(info_tx).fuse() => {}
    }
    Ok(())
}

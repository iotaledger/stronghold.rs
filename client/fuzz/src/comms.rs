//! Copyright 2021 IOTA Stiftung
//! SPDX-License-Identifier: Apache-2.0
//!
//! Stronghold communications fuzzer

#![no_main]

use iota::{Location, Multiaddr, PeerId, ResultMessage};
use iota_stronghold as iota;
use libfuzzer_sys::fuzz_target;
use log::*;
use redis::{self, Client, Commands};
use std::{error::Error, str::FromStr};
use tokio::runtime::Runtime;
use Location::Generic;

const REDIS_KEY_PEER_ID: &str = "peer_id";
const REDIS_KEY_MULTI_ADDR: &str = "multiaddr";
const REDIS_INSTANCE_ADDR: &str = "redis://config";

/// Parses a comma separated [`Multiaddr`]
async fn parse_multiaddr(input: String) -> Result<Vec<Multiaddr>, Box<dyn Error>> {
    let mut result = Vec::new();
    for token in input.split(",") {
        let addr = Multiaddr::from_str(token)?;
        result.push(addr);
    }
    Ok(result)
}

/// Connects to a `config` named redis instance, tries to read the [`PeerId`] and [`Multiaddr`]
/// and returns them.
async fn read_infos(timeout: u64) -> Result<(PeerId, Vec<Multiaddr>), Box<dyn Error>> {
    let client = Client::open(REDIS_INSTANCE_ADDR)?;
    let mut connection = client.get_connection_with_timeout(std::time::Duration::from_millis(timeout))?;
    let p: String = connection.get(REDIS_KEY_PEER_ID)?;
    let m: String = connection.get(REDIS_KEY_MULTI_ADDR)?;
    let peer_id = PeerId::from_str(p.as_str())?;

    let multiaddr: Vec<Multiaddr> = parse_multiaddr(m).await?;

    Ok((peer_id, multiaddr))
}

fuzz_target!(|data: &[u8]| {
    let runtime = Runtime::new().unwrap();
    let system = iota::ActorSystem::new().unwrap();
    let mut stronghold = iota::Stronghold::init_stronghold_system(system, b"client".to_vec(), vec![]);

    stronghold.spawn_communication();

    runtime.block_on(async {
        match read_infos(200).await {
            Ok((peer_id, addr)) => {
                // println("Got Peer: {}, multiaddr: {}", peer_id, addr);

                // 1. Fuzz Write To Store
                let vid = b"storepath_0";
                let rid = b"recordpath_0";

                // add peer from information given via redis
                let mut addr_it = addr.into_iter();
                while let ResultMessage::Error(e) = stronghold.add_peer(peer_id, addr_it.next(), None).await {
                    error!("{}", e);
                }

                info!("Write to remote store");
                // write to remote store
                stronghold
                    .write_to_remote_store(
                        peer_id,
                        Generic {
                            vault_path: vid.to_vec(),
                            record_path: rid.to_vec(),
                        },
                        data.to_vec(),
                        None,
                    )
                    .await;

                info!("Read from remote store");
                // re-read the payload
                let (result, _) = stronghold
                    .read_from_remote_store(
                        peer_id,
                        Generic {
                            vault_path: vid.to_vec(),
                            record_path: rid.to_vec(),
                        },
                    )
                    .await;

                info!("Compare written payload");
                // assert written payload
                assert_eq!(result, data.to_vec());

                // 2. Fuzz Storage Location

                // 3. Fuzz Records Id

                // 4. Fuzz Storage Location, Records Id, Payload
            }
            Err(e) => {
                error!("{}", e);
            }
        };
    });
});

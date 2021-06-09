//! Copyright 2021 IOTA Stiftung
//! SPDX-License-Identifier: Apache-2.0
//!
//! Stronghold communications fuzzer util.
//!
//! This module keeps a running stronghold instance for
//! receiving fuzzed data.

use iota::Multiaddr;
use iota_stronghold as iota;
use redis::{Client, Commands};
use std::{error::Error, str::FromStr};

const REDIS_KEY_PEER_ID: &str = "peer_id";
const REDIS_KEY_MULTI_ADDR: &str = "multiaddr";
const REDIS_INSTANCE_ADDR: &str = "redis://config";

/// Callback type for blocking stronghold instance
type Callback = fn() -> Result<(), Box<dyn Error>>;

/// this fn will be used in a dockerized context to write infos
/// like peer_id, multiaddress into a redis slot.
async fn write_infos(timeout: u64, peer_id: String, multiaddr: String) -> Result<(), Box<dyn Error>> {
    let client = Client::open(REDIS_INSTANCE_ADDR)?;
    let mut connection = client.get_connection_with_timeout(std::time::Duration::from_millis(timeout))?;

    connection.set::<String, String, ()>(REDIS_KEY_PEER_ID.to_string(), peer_id)?;
    connection.set::<String, String, ()>(REDIS_KEY_MULTI_ADDR.to_string(), multiaddr)?;

    Ok(())
}

fn main() {
    let system = iota::ActorSystem::new().unwrap();
    let options = vec![];
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let client_path = b"client_path".to_vec();

    let mut stronghold = iota::Stronghold::init_stronghold_system(system, client_path, options);

    // communications fuzzing
    stronghold.spawn_communication();

    runtime.block_on(async {
        stronghold
            .start_listening(Some(Multiaddr::from_str("/ip4/0.0.0.0/tcp/7001").unwrap()))
            .await;

        if let iota::ResultMessage::Ok((id, v_address, _)) = stronghold.get_swarm_info().await {
            let addr: Vec<String> = v_address.iter().map(|f| f.to_string()).collect();

            write_infos(200, id.to_base58(), addr.join(","))
                .await
                .expect("Could not write infos");

            println!("peer_id: {:#?}", id.to_base58());
        }
    });

    // block execution
    stronghold.keep_alive(None::<Callback>);
}

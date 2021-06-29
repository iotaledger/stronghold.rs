// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stronghold communications fuzzer

#![no_main]

use iota::{Location, Multiaddr, PeerId, ProcResult, RecordHint, ResultMessage};
use iota_stronghold as iota;
use libfuzzer_sys::fuzz_target;
use log::*;
use std::sync::Arc;
use std::{collections::HashMap, error::Error, str::FromStr, sync::Mutex};
use tokio::runtime::Runtime;
use Location::Generic;

const REDIS_KEY_PEER_ID: &str = "peer_id";
const REDIS_KEY_MULTI_ADDR: &str = "multiaddr";

/// Parses a comma separated [`Multiaddr`]
async fn parse_multiaddr(input: String) -> Result<Vec<Multiaddr>, Box<dyn Error>> {
    let mut result = Vec::new();
    for token in input.split(",") {
        let addr = Multiaddr::from_str(token)?;
        result.push(addr);
    }
    Ok(result)
}

async fn read_infos(
    map: Arc<Mutex<HashMap<&'static str, String>>>,
) -> Result<(PeerId, Vec<Multiaddr>), Box<dyn Error>> {
    let map = map.lock().unwrap();
    let p = map.get(&REDIS_KEY_PEER_ID).unwrap();
    let m = map.get(&REDIS_KEY_MULTI_ADDR).unwrap();

    let peer_id = PeerId::from_str(p.as_str())?;

    let multiaddr: Vec<Multiaddr> = parse_multiaddr(m.clone()).await?;

    Ok((peer_id, multiaddr))
}

async fn start_listener(map: Arc<Mutex<HashMap<&'static str, String>>>) -> iota::Stronghold {
    let system = iota::ActorSystem::new().unwrap();
    let options = vec![];

    let client_path = b"client_path".to_vec();

    let mut stronghold = iota::Stronghold::init_stronghold_system(system, client_path, options);

    // communications fuzzing
    stronghold.spawn_communication();

    stronghold
        .start_listening(Some(Multiaddr::from_str("/ip4/0.0.0.0/tcp/7001").unwrap()))
        .await;

    if let iota::ResultMessage::Ok((id, v_address, _)) = stronghold.get_swarm_info().await {
        let addr: String = v_address
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<String>>()
            .join(",");

        map.lock().unwrap().insert(REDIS_KEY_PEER_ID, id.to_base58());
        map.lock().unwrap().insert(REDIS_KEY_MULTI_ADDR, addr.clone());

        info!("LISTENING ON: peer_id: {:#?}, addr {:?}", id.to_base58(), addr);
    }

    stronghold
}

fuzz_target!(|data: &[u8]| {
    let runtime = Runtime::new().unwrap();
    let map = Arc::from(Mutex::from(HashMap::new()));
    let listener = runtime.block_on(start_listener(map.clone()));

    info!("connecting to listener");
    let system = iota::ActorSystem::new().unwrap();
    let mut stronghold = iota::Stronghold::init_stronghold_system(system, b"client".to_vec(), vec![]);

    stronghold.spawn_communication();

    runtime.block_on(async move {
        match read_infos(map.clone()).await {
            Ok((peer_id, addr)) => {
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
                info!("Write fuzzed storage location");
                let payload = b"unfuzzed".to_vec();

                stronghold
                    .write_to_remote_store(
                        peer_id,
                        Generic {
                            vault_path: data.to_vec(),
                            record_path: data.to_vec(),
                        },
                        payload.clone(),
                        None,
                    )
                    .await;

                info!("Read fuzzed storage location");

                let (result, _) = stronghold
                    .read_from_remote_store(
                        peer_id,
                        Generic {
                            vault_path: data.to_vec(),
                            record_path: data.to_vec(),
                        },
                    )
                    .await;

                assert_eq!(result, payload);

                // 3. Fuzz Remote Procedure Calls
                info!("Fuzz Remote Procedure Calls: BIP39");
                let result = stronghold
                    .remote_runtime_exec(
                        peer_id,
                        iota::Procedure::BIP39Generate {
                            hint: RecordHint::new(b"hint").unwrap(),
                            output: Generic {
                                vault_path: data.to_vec(),
                                record_path: data.to_vec(),
                            },
                            passphrase: Some("test_pwd".to_string()),
                        },
                    )
                    .await;

                match result {
                    ProcResult::BIP39Generate(msg) => {
                        assert!(msg.is_ok());
                    }
                    _ => {}
                };

                info!("Fuzz Remote Procedure Calls: SLIP10Generator");
                let result = stronghold
                    .remote_runtime_exec(
                        peer_id,
                        iota::Procedure::SLIP10Generate {
                            hint: RecordHint::new(b"hint").unwrap(),
                            output: Generic {
                                vault_path: data.to_vec(),
                                record_path: data.to_vec(),
                            },
                            size_bytes: Some(64),
                        },
                    )
                    .await;

                match result {
                    ProcResult::SLIP10Generate(msg) => {
                        assert!(msg.is_ok());
                    }
                    _ => {}
                };

                // 4. Fuzz write into vault
                info!("Fuzzed Write Into Remote Vault");
                stronghold
                    .write_remote_vault(
                        peer_id,
                        Generic {
                            record_path: b"record_path".to_vec(),
                            vault_path: b"vault_path".to_vec(),
                        },
                        payload,
                        RecordHint::new(b"record_hint").unwrap(),
                        vec![],
                    )
                    .await;
            }
            Err(e) => {
                // force exit
                panic!("{}", e);
            }
        };
        listener.stop_listening().await;
        drop(listener);
        drop(stronghold);
    });
});

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{future, sync::Arc, time::Duration};

use engine::vault::RecordHint;
use stronghold_p2p::{
    identity::{Keypair, PublicKey},
    AddressInfo, OutboundFailure, PeerId,
};
// use crate::{
//     network::{ClientAccess, FirewallChannel},
//     p2p::{identity::Keypair, NetworkConfig, OutboundFailure, P2pError, PeerId, Permissions, SwarmInfo},
//     procedures::{Slip10Derive, Slip10DeriveInput, Slip10Generate},
//     state::p2p::{ClientAccess, FirewallChannel, FirewallChannelSender},
//     // tests::fresh,
//     Location,
//     Stronghold,
// };
use crypto::{keys::slip10::Chain, utils::rand as crypto_rand};
use futures::SinkExt;
use stronghold_utils::random as rand;
use tokio::sync::{mpsc, oneshot};

use crate::{
    network_old::{
        ClientAccess, FirewallChannel, FirewallChannelSender, NetworkConfig, Permissions, StrongholdNetworkResult,
    },
    procedures::{Slip10Derive, Slip10DeriveInput, Slip10Generate},
    Location, P2pError, Stronghold, SwarmInfo,
};

/// Creates a random [`RecordHint`]
pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    crypto_rand::fill(&mut bs).expect("Unable to fill record hint");
    bs.into()
}

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(rand::bytestring(4096), rand::bytestring(4096))
}

/// generates a random string based on a coinflip.
pub fn passphrase() -> Option<String> {
    if rand::coinflip() {
        Some(rand::string(4096))
    } else {
        None
    }
}

/// Creates a random hd_path.
pub fn hd_path() -> (String, Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while rand::coinflip() {
        let i = rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i));
        is.push(i);
    }
    (s, Chain::from_u32_hardened(is))
}

struct Setup {
    local_stronghold: Stronghold,
    local_id: PeerId,
    remote_stronghold: Stronghold,
    remote_id: PeerId,
    remote_client: Vec<u8>,
}

enum FirewallSetup {
    Async(FirewallChannelSender),
    Fixed(Permissions),
}

impl Default for FirewallSetup {
    fn default() -> Self {
        FirewallSetup::Fixed(Permissions::allow_all())
    }
}

// Init local and remote Stronghold, start listening on the remote and add the address info to the local peer.
async fn spawn_peers(remote_firewall_config: FirewallSetup, store_keys: Option<Location>) -> Setup {
    // let remote_client_path = rand::bytestring(4096);

    // // Start remote stronghold and start listening
    // let mut remote_stronghold = Stronghold::default();

    // let (permissions, firewall_tx) = match remote_firewall_config {
    //     FirewallSetup::Fixed(p) => (p, None),
    //     FirewallSetup::Async(firewall_tx) => (Permissions::allow_none(), Some(firewall_tx)),
    // };
    // let mut config = NetworkConfig::new(permissions).with_mdns_enabled(false);
    // if let Some(tx) = firewall_tx {
    //     config = config.with_async_firewall(tx);
    // }

    // assert!(remote_stronghold
    //     .spawn_p2p(remote_client_path.clone(), config, None)
    //     .await
    //     .is_ok());

    // let remote_addr = match remote_stronghold.start_listening(None).await {
    //     Ok(a) => a,
    //     Err(e) => panic!("Unexpected error {}", e),
    // };
    // let SwarmInfo {
    //     local_peer_id: remote_id,
    //     ..
    // } = remote_stronghold.get_swarm_info().await;

    // // Start local stronghold.
    // let client_path = rand::bytestring(4096);
    // let mut local_stronghold = Stronghold::default();
    // let local_client = local_stronghold.load_client(client_path.clone()).await.unwrap();

    // let fixed_keys = match store_keys {
    //     Some(keys_location) => {
    //         // Generate a new Keypair and write it to the vault
    //         let keypair = Keypair::generate_ed25519();
    //         let peer_id = PeerId::from_public_key(&keypair.public());

    //         match local_client.write_p2p_keypair(keypair, keys_location.clone()) {
    //             Ok(()) => Some((peer_id, keys_location)),
    //             Err(e) => panic!("Unexpected error {}", e),
    //         }
    //     }
    //     None => None,
    // };

    // let key_location = fixed_keys.as_ref().map(|(_, loc)| loc.clone());

    // match local_stronghold
    //     .spawn_p2p(
    //         client_path,
    //         NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(false),
    //         key_location,
    //     )
    //     .await
    // {
    //     Ok(()) => {}
    //     Err(e) => panic!("Unexpected error {}", e),
    // }

    // let SwarmInfo { local_peer_id, .. } = local_stronghold.get_swarm_info().await;
    // if let Some((id, _)) = fixed_keys {
    //     assert_eq!(local_peer_id, id);
    // }

    // // Add the remote's address info
    // match local_stronghold.add_peer(remote_id, Some(remote_addr)).await {
    //     Ok(_) => {}
    //     Err(e) => panic!("Unexpected error {}", e),
    // }

    // Setup {
    //     local_stronghold,
    //     remote_stronghold,
    //     local_id: local_peer_id,
    //     remote_id,
    //     remote_client: remote_client_path,
    // }

    todo!()
}

#[tokio::test]
async fn test_stronghold_p2p_old() {
    // let system = actix::System::current();
    // let arbiter = system.arbiter();

    // let Setup {
    //     local_stronghold,
    //     remote_stronghold,
    //     remote_id,
    //     remote_client,
    //     ..
    // } = spawn_peers(FirewallSetup::default(), None).await;
    // let remote_client_clone = remote_client.clone();

    // // Channel for signaling that local/ remote is ready, it performed a necessary write, before the other can try
    // // reading.
    // let (remote_ready_tx, mut remote_ready_rx) = mpsc::channel(1);
    // let (local_ready_tx, mut local_ready_rx) = mpsc::channel(1);

    // let key1 = rand::bytestring(1024);
    // let data1 = b"some data".to_vec();
    // let key1_clone = key1.clone();
    // let data1_clone = data1.clone();

    // let key2 = rand::bytestring(1024);
    // let data2 = b"some second data".to_vec();
    // let key2_clone = key2.clone();
    // let data2_clone = data2.clone();

    // let seed1 = location();
    // let seed1_clone = seed1.clone();

    // let (thread_done_tx, mut thread_done_rx) = mpsc::channel(1);
    // let thread_done_tx_clone = thread_done_tx.clone();

    // let spawned_local = tokio::spawn(async move {
    //     remote_ready_rx.recv().await.unwrap();

    //     // TEST 1: writing at remote and reading it from local stronghold
    //     let payload = local_stronghold
    //         .read_from_remote_store(remote_id, remote_client_clone.clone(), key1)
    //         .await
    //         .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
    //     assert_eq!(payload.unwrap(), data1);

    //     // TEST 2: writing from local and reading it at remote
    //     local_stronghold
    //         .write_to_remote_store(remote_id, remote_client_clone.clone(), key2, data2, None)
    //         .await
    //         .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));
    //     local_ready_tx.send(()).await.unwrap();

    //     // TEST 3: writing and reading from local
    //     let key3 = rand::bytestring(1024);
    //     let original_data3 = b"some third data".to_vec();
    //     local_stronghold
    //         .write_to_remote_store(
    //             remote_id,
    //             remote_client_clone.clone(),
    //             key3.clone(),
    //             original_data3.clone(),
    //             None,
    //         )
    //         .await
    //         .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

    //     let payload = local_stronghold
    //         .read_from_remote_store(remote_id, remote_client_clone.clone(), key3)
    //         .await
    //         .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));

    //     assert_eq!(payload.unwrap(), original_data3);

    //     remote_ready_rx.recv().await.unwrap();

    //     let (_path, chain) = hd_path();

    //     // TEST 4: procedure execution from local
    //     match local_stronghold
    //         .remote_procedure_exec(
    //             remote_id,
    //             remote_client_clone,
    //             Slip10Derive {
    //                 output: location(),
    //                 chain,
    //                 hint: record_hint(),
    //                 input: Slip10DeriveInput::Seed(seed1),
    //             },
    //         )
    //         .await
    //         .unwrap_or_else(|e| panic!("Could not execute remote procedure: {}", e))
    //     {
    //         Ok(_) => {}
    //         Err(e) => panic!("unexpected error: {:?}", e),
    //     };

    //     thread_done_tx.send(()).await.unwrap();
    // });
    // assert!(spawned_local.await.is_ok());

    // let spawned_remote = tokio::spawn(async move {
    //     // TEST 1: writing at remote and reading it from local stronghold
    //     let client = remote_stronghold.load_client(remote_client).await.unwrap();
    //     let store = client.store();

    //     store
    //         .insert(key1_clone, data1_clone, None)
    //         .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

    //     remote_ready_tx.send(()).await.unwrap();
    //     local_ready_rx.recv().await.unwrap();

    //     // TEST 2: writing from local and reading it at remote
    //     let store_result = store.get(key2_clone);
    //     let payload = store_result
    //         .unwrap()
    //         .unwrap_or_else(|| panic!("Could not read from remote store"));

    //     assert_eq!(payload, data2_clone);

    //     // TEST 5: procedure execution at remote
    //     match client.execute_procedure(Slip10Generate {
    //         size_bytes: None,
    //         output: seed1_clone,
    //         hint: record_hint(),
    //     }) {
    //         Ok(_) => {}
    //         Err(e) => panic!("Could not execute procedure: {:?}", e),
    //     };

    //     remote_ready_tx.send(()).await.unwrap();

    //     thread_done_tx_clone.send(()).await.unwrap();
    // });
    // assert!(spawned_remote.await.is_ok());

    // // wait for both threads to return
    // thread_done_rx.recv().await.unwrap();
    // thread_done_rx.recv().await.unwrap();
}

#[tokio::test]
async fn test_p2p_config_old() {
    // let keys_location = location();
    // let local_client_path = rand::bytestring(24);

    // let Setup {
    //     mut local_stronghold,
    //     local_id,
    //     remote_stronghold,
    //     remote_id,
    //     remote_client,
    // } = spawn_peers(FirewallSetup::default(), Some(keys_location.clone())).await;

    // // Set a firewall rule
    // remote_stronghold
    //     .set_peer_permissions(Permissions::default(), local_id)
    //     .await
    //     .unwrap();

    // // Test that the firewall rule is effective
    // let res = local_stronghold
    //     .read_from_remote_store(remote_id, remote_client.clone(), rand::bytestring(10))
    //     .await;
    // match res {
    //     Ok(_) => panic!("Request should be rejected."),
    //     Err(P2pError::Local(e)) => panic!("Unexpected error {}", e),
    //     Err(P2pError::SendRequest(OutboundFailure::DialFailure))
    //     | Err(P2pError::SendRequest(OutboundFailure::Shutdown))
    //     | Err(P2pError::SendRequest(OutboundFailure::Timeout)) => panic!("Unexpected error {:?}", res),
    //     Err(_) => {}
    // }

    // // Stop p2p and store the config in the stronghold store.
    // // This should persist firewall configuration and the collected address info about the remote.
    // let store_bogus = rand::bytestring(1024);
    // match local_stronghold.stop_p2p(Some(store_bogus.clone())).await {
    //     Ok(()) => {}
    //     Err(e) => panic!("Unexpected error {}", e),
    // }

    // // Spawn p2p again and load the config. Use the same keypair to keep the same peer-id.
    // match local_stronghold
    //     .spawn_p2p_load_config(local_client_path, store_bogus, Some(keys_location), None)
    //     .await
    // {
    //     Ok(()) => {}
    //     Err(e) => panic!("Unexpected error {}", e),
    // }
    // let SwarmInfo { local_peer_id, .. } = local_stronghold.get_swarm_info().await;
    // assert_eq!(local_peer_id, local_id);

    // // Test if the local peer still has the remote's address info.
    // match local_stronghold.add_peer(remote_id, None).await {
    //     Ok(_) => {}
    //     Err(e) => panic!("Unexpected error {}", e),
    // }
    // // Test that the firewall rule is still effective
    // let res = local_stronghold
    //     .read_from_remote_store(remote_id, remote_client, rand::bytestring(10))
    //     .await;
    // match res {
    //     Ok(_) => panic!("Request should be rejected."),
    //     Err(P2pError::Local(e)) => panic!("Unexpected error {}", e),
    //     Err(P2pError::SendRequest(OutboundFailure::DialFailure))
    //     | Err(P2pError::SendRequest(OutboundFailure::Shutdown))
    //     | Err(P2pError::SendRequest(OutboundFailure::Timeout)) => panic!("Unexpected error {:?}", res),
    //     Err(_) => {}
    // }
}

#[tokio::test]
async fn test_p2p_firewall_old() {
    // let (firewall_tx, mut firewall_rx) = FirewallChannel::new();

    // let Setup {
    //     local_stronghold,
    //     local_id,
    //     mut remote_stronghold,
    //     remote_id,
    //     remote_client,
    // } = spawn_peers(FirewallSetup::Async(firewall_tx), None).await;

    // let forbidden_client_path = rand::bytestring(1024);
    // let remote_client = remote_stronghold.load_client(forbidden_client_path).await.unwrap();

    // // remote_stronghold
    // //     .spawn_stronghold_actor(forbidden_client_path.clone(), vec![])
    // //     .await
    // //     .unwrap();

    // let allowed_client_path = remote_client;
    // let allowed_client_path_clone = allowed_client_path.clone();

    // let allowed_vault_path = rand::bytestring(1024);
    // let allowed_vault_path_clone = allowed_vault_path.clone();

    // let spawned_remote = tokio::spawn(async move {
    //     let _ = remote_stronghold;
    //     // Permissions requests issued by the write attempt of `local_stronghold`.
    //     let permission_setter = firewall_rx.select_next_some().await;
    //     assert_eq!(permission_setter.peer(), local_id);

    //     // Allow `write` only on vault `allowed_vault_path_clone` in client `allowed_client_path_clone`.
    //     let client_permissions =
    //         ClientAccess::allow_none().with_vault_access(allowed_vault_path_clone, false, true, false);
    //     let permissions =
    //         Permissions::allow_none().with_client_permissions(allowed_client_path_clone, client_permissions);
    //     permission_setter.set_permissions(permissions).unwrap();
    // });
    // assert!(spawned_remote.await.is_ok());

    // let (done_tx, done_rx) = oneshot::channel();
    // let spawned_local = tokio::spawn(async move {
    //     let loc1 = Location::generic(allowed_vault_path.clone(), rand::bytestring(1024));

    //     let res = local_stronghold
    //         .write_remote_vault(
    //             remote_id,
    //             allowed_client_path.clone(),
    //             loc1.clone(),
    //             rand::bytestring(1024),
    //             record_hint(),
    //         )
    //         .await
    //         .map(|ok| ok.unwrap());
    //     assert!(res.is_ok());

    //     let res = local_stronghold
    //         .write_remote_vault(
    //             remote_id,
    //             forbidden_client_path.clone(),
    //             loc1,
    //             rand::bytestring(1024),
    //             record_hint(),
    //         )
    //         .await
    //         .map(|ok| ok.unwrap());
    //     // Firewall at the remote rejected the request to the invalid client path.
    //     assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

    //     let loc2 = Location::generic(allowed_client_path.clone(), rand::bytestring(1024));
    //     let res = local_stronghold
    //         .write_remote_vault(
    //             remote_id,
    //             allowed_client_path.clone(),
    //             loc2,
    //             rand::bytestring(1024),
    //             record_hint(),
    //         )
    //         .await
    //         .map(|ok| ok.unwrap());
    //     // Firewall at the remote rejected the request to the invalid vault path.
    //     assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

    //     let loc3 = Location::generic(allowed_vault_path.clone(), rand::bytestring(1024));
    //     let proc_generate = Slip10Generate {
    //         size_bytes: None,
    //         output: loc3.clone(),
    //         hint: record_hint(),
    //     };

    //     let loc4 = Location::generic(allowed_vault_path.clone(), rand::bytestring(1024));
    //     let proc_derive = Slip10Derive {
    //         input: Slip10DeriveInput::Seed(loc3),
    //         chain: hd_path().1,
    //         output: loc4,
    //         hint: record_hint(),
    //     };

    //     let res = local_stronghold
    //         .remote_procedure_exec_chained(
    //             remote_id,
    //             allowed_client_path.clone(),
    //             vec![proc_generate.into(), proc_derive.into()],
    //         )
    //         .await
    //         .map(|ok| ok.unwrap());
    //     // Firewall at the remote rejected the request  because only `write` is allowed, but not
    //     // `use`, which is required for the `Slip10Derive`.
    //     assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

    //     // Counter check that Slip10Generate on its own works.
    //     let loc5 = Location::generic(allowed_vault_path.clone(), rand::bytestring(1024));
    //     let proc_generate = Slip10Generate {
    //         size_bytes: None,
    //         output: loc5,
    //         hint: record_hint(),
    //     };
    //     let res = local_stronghold
    //         .remote_procedure_exec(remote_id, allowed_client_path.clone(), proc_generate)
    //         .await
    //         .map(|ok| ok.unwrap());
    //     assert!(res.is_ok());

    //     done_tx.send(()).unwrap()
    // });
    // assert!(spawned_local.await.is_ok());

    // done_rx.await.unwrap();
}

#[tokio::test]
async fn test_p2p_cycle() {
    // -- setup
    let key_pair = Keypair::generate_ed25519();
    let remote_client_path = rand::bytestring(1024);
    let remote = Stronghold::default();
    let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(false);

    // we need to create a client on the remote that accepts incoming requests
    let _ = remote
        .create_client(remote_client_path.clone())
        .expect("Failed to create Peer");

    let result = remote.spawn_p2p(remote_client_path, config, None).await;
    assert!(result.is_ok(), "Assertion Failed=  {:?}", result);

    let (mut sender_terminate_signal, receiver_terminate_signal) = futures::channel::mpsc::unbounded();

    let result = remote.start_listening(None).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // clone remote which will be moved into a background task
    let remote_stronghold_server = remote.clone();

    // keep handle to server
    let server = tokio::spawn(async move { remote_stronghold_server.serve(receiver_terminate_signal).await });

    // --- tear down ---
    // send termination signal
    let result = sender_terminate_signal.send(()).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // await server event loop shutdown
    let result = server.await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // shutdown listening
    let result = remote.stop_listening().await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);
}

#[tokio::test]
async fn test_p2p_write_read_delete_remote_store() {
    // -- setup
    let remote_key_pair = Keypair::generate_ed25519();
    let remote_public_key = remote_key_pair.public();
    let remote_key_path = Location::generic(b"remote-key-path".to_vec(), b"remote-key-path".to_vec());
    let remote_client_path = rand::bytestring(1024);
    let remote = Stronghold::default();
    let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(true);

    // we need to create a client on the remote that accepts incoming requests
    let result = remote.create_client(remote_client_path.clone());
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    let client = result.unwrap();
    let result = client.write_p2p_keypair(remote_key_pair, remote_key_path.clone());
    assert!(result.is_ok(), "Assertion Failed=  {:?}", result);

    let result = remote
        .spawn_p2p(remote_client_path.clone(), config, Some(remote_key_path))
        .await;
    assert!(result.is_ok(), "Assertion Failed=  {:?}", result);

    let (mut sender_terminate_signal, receiver_terminate_signal) = futures::channel::mpsc::unbounded();

    let result = remote.start_listening(None).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    let remote_address = result.unwrap();

    let remote_peer_id = PeerId::from_public_key(&remote_public_key);

    // clone remote which will be moved into a background task
    let remote_stronghold_server = remote.clone();

    // keep handle to server
    let server = tokio::spawn(async move { remote_stronghold_server.serve(receiver_terminate_signal).await });
    // tests come here
    {
        let local_client_path = rand::bytestring(1024);
        let local_key_pair = Keypair::generate_ed25519();
        let local_public_key = local_key_pair.public();
        let local_key_path = Location::generic(b"keypair-path".to_vec(), b"keypair-path".to_vec());
        let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(true);
        let local = Stronghold::default();

        let result = local.create_client_with_keys(local_client_path.clone(), local_key_pair, local_key_path);
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let result = local.spawn_p2p(local_client_path, config, None).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let result = local.add_peer_addr(remote_peer_id, remote_address).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let local_address = result.unwrap();
        let result = remote
            .add_peer_addr(PeerId::from_public_key(&local_public_key), local_address)
            .await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        // create peer
        let result = local.create_remote_client(remote_public_key, remote_client_path).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        // connect peer
        let peer = result.unwrap();
        let result = peer.connect().await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        //  run this test a couple of times
        for _ in 0..10 {
            let key = rand::bytestring(1024);
            let data = rand::bytestring(1024);

            let result = peer.remote_write_store(key.clone(), data.clone(), None).await;
            assert!(result.is_ok(), "Assertion Failed= {:?}", result);

            let result = peer.remote_read_store(key.clone()).await;
            assert!(result.is_ok(), "Assertion Failed= {:?}", result);

            let result = peer.remote_delete_store(key).await;
            assert!(result.is_ok(), "Assertion Failed= {:?}", result);

            if let StrongholdNetworkResult::Data(recv_data) = result.unwrap() {
                assert!(recv_data.is_none(), "Received data where it should be None");
            }
        }
    }

    // --- tear down ---
    // send termination signal
    let result = sender_terminate_signal.send(()).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // await server event loop shutdown
    let result = server.await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // shutdown listening
    let result = remote.stop_listening().await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);
}

#[tokio::test]
async fn test_p2p_write_read_to_remote_store() {
    // -- setup
    let remote_key_pair = Keypair::generate_ed25519();
    let remote_public_key = remote_key_pair.public();
    let remote_key_path = Location::generic(b"remote-key-path".to_vec(), b"remote-key-path".to_vec());
    let remote_client_path = rand::bytestring(1024);
    let remote = Stronghold::default();
    let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(true);

    // we need to create a client on the remote that accepts incoming requests
    let result = remote.create_client(remote_client_path.clone());
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    let client = result.unwrap();
    let result = client.write_p2p_keypair(remote_key_pair, remote_key_path.clone());
    assert!(result.is_ok(), "Assertion Failed=  {:?}", result);

    let result = remote
        .spawn_p2p(remote_client_path.clone(), config, Some(remote_key_path))
        .await;
    assert!(result.is_ok(), "Assertion Failed=  {:?}", result);

    let (mut sender_terminate_signal, receiver_terminate_signal) = futures::channel::mpsc::unbounded();

    let result = remote.start_listening(None).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    let remote_address = result.unwrap();

    let remote_peer_id = PeerId::from_public_key(&remote_public_key);

    // clone remote which will be moved into a background task
    let remote_stronghold_server = remote.clone();

    // keep handle to server
    let server = tokio::spawn(async move { remote_stronghold_server.serve(receiver_terminate_signal).await });
    // tests come here
    {
        let local_client_path = rand::bytestring(1024);
        let local_key_pair = Keypair::generate_ed25519();
        let local_public_key = local_key_pair.public();
        let local_key_path = Location::generic(b"keypair-path".to_vec(), b"keypair-path".to_vec());
        let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(true);
        let local = Stronghold::default();

        let result = local.create_client_with_keys(local_client_path.clone(), local_key_pair, local_key_path);
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let result = local.spawn_p2p(local_client_path, config, None).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let result = local.add_peer_addr(remote_peer_id, remote_address).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        let local_address = result.unwrap();
        let result = remote
            .add_peer_addr(PeerId::from_public_key(&local_public_key), local_address)
            .await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        // create peer
        let result = local.create_remote_client(remote_public_key, remote_client_path).await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        // connect peer
        let peer = result.unwrap();
        let result = peer.connect().await;
        assert!(result.is_ok(), "Assertion Failed= {:?}", result);

        //  run this test a couple of times
        for _ in 0..10 {
            let key = rand::bytestring(1024);
            let data = rand::bytestring(1024);

            let result = peer.remote_write_store(key.clone(), data.clone(), None).await;
            assert!(result.is_ok(), "Assertion Failed= {:?}", result);

            let result = peer.remote_read_store(key).await;
            assert!(result.is_ok(), "Assertion Failed= {:?}", result);

            if let StrongholdNetworkResult::Data(recv_data) = result.unwrap() {
                assert!(recv_data.is_some(), "Received data is None");
                assert_eq!(recv_data.unwrap(), data);
            }
        }
    }

    // --- tear down ---
    // send termination signal
    let result = sender_terminate_signal.send(()).await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // await server event loop shutdown
    let result = server.await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // shutdown listening
    let result = remote.stop_listening().await;
    assert!(result.is_ok(), "Assertion Failed= {:?}", result);
}

/// This tests creates two instances of Stronghold:
/// - a server instance with some key to run some procedures against
/// - a client instance that retrieves a Peer from the remote instances and calls remote procedures
///
/// The server instance creates an ephemeral key stored under a client defined by a `client_path`. The public key
/// of the client, will be used to remotely execute function calls.
#[tokio::test]
async fn test_p2p_config() {
    // let remote_client_path = rand::bytestring(1024);
    // let remote = Stronghold::default();
    // let config = NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(false);

    // // generate a new keypair
    // let remote_keypair = Keypair::generate_ed25519();
    // let remote_keypair_location =
    //     Location::const_generic(b"remote-keypair-location".to_vec(), b"remote-keypair-location".to_vec());
    // let _ = remote.create_client_with_keys(
    //     remote_client_path.clone(),
    //     remote_keypair,
    //     remote_keypair_location.clone(),
    // );

    // let result = remote.create_client(remote_client_path.clone());
    // assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // let result = remote
    //     .spawn_p2p(remote_client_path, config, Some(remote_keypair_location))
    //     .await;
    // assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // let (mut sender_terminate_signal, receiver_terminate_signal) = futures::channel::mpsc::unbounded();

    // let result = remote.start_listening(None).await;
    // assert!(result.is_ok(), "Assertion Failed= {:?}", result);

    // // keep handle to server
    // let stronghold_clone = remote.clone();
    // let server = tokio::spawn(async move { stronghold_clone.serve(receiver_terminate_signal).await });

    // // test cases here
    // // ..

    // // send termination signal
    // assert!(sender_terminate_signal.send(()).await.is_ok());

    // // await server event loop shutdown
    // assert!(server.await.is_ok());

    // // shutdown listening
    // let result = remote.stop_listening().await;
    // println!("stop listening: {:?}", result);
    // assert!(result.is_ok());
}
#[tokio::test]
async fn test_p2p_firewall() {
    //
}

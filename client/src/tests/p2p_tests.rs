// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    p2p::{identity::Keypair, NetworkConfig, OutboundFailure, P2pError, PeerId, Permissions, SwarmInfo},
    procedures::{Slip10Derive, Slip10DeriveInput, Slip10Generate},
    state::p2p::{ClientAccess, FirewallChannel, FirewallChannelSender},
    tests::fresh,
    Location, Stronghold,
};
use futures::StreamExt;
use stronghold_utils::random::bytestring;
use tokio::sync::{mpsc, oneshot};

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
    let remote_client = bytestring(4096);
    // Start remote stronghold and start listening
    let mut remote_sh = Stronghold::init_stronghold_system(remote_client.clone(), vec![])
        .await
        .unwrap();
    let (permissions, firewall_tx) = match remote_firewall_config {
        FirewallSetup::Fixed(p) => (p, None),
        FirewallSetup::Async(firewall_tx) => (Permissions::allow_none(), Some(firewall_tx)),
    };
    let mut config = NetworkConfig::new(permissions).with_mdns_enabled(false);
    if let Some(tx) = firewall_tx {
        config = config.with_async_firewall(tx);
    }
    match remote_sh.spawn_p2p(config, None).await {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    let remote_addr = match remote_sh.start_listening(None).await.unwrap() {
        Ok(a) => a,
        Err(e) => panic!("Unexpected error {}", e),
    };
    let SwarmInfo {
        local_peer_id: remote_id,
        ..
    } = remote_sh.get_swarm_info().await.unwrap();

    // Start local stronghold.
    let client_path = fresh::bytestring(4096);
    let mut local_sh = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    let fixed_keys = match store_keys {
        Some(keys_location) => {
            // Generate a new Keypair and write it to the vault
            let keypair = Keypair::generate_ed25519();
            let peer_id = PeerId::from_public_key(&keypair.public());
            match local_sh
                .write_p2p_keypair(keypair, keys_location.clone(), fresh::record_hint())
                .await
                .unwrap()
            {
                Ok(()) => Some((peer_id, keys_location)),
                Err(e) => panic!("Unexpected error {}", e),
            }
        }
        None => None,
    };

    let key_location = fixed_keys.as_ref().map(|(_, loc)| loc.clone());

    match local_sh
        .spawn_p2p(
            NetworkConfig::new(Permissions::allow_all()).with_mdns_enabled(false),
            key_location,
        )
        .await
    {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }

    let SwarmInfo { local_peer_id, .. } = local_sh.get_swarm_info().await.unwrap();
    if let Some((id, _)) = fixed_keys {
        assert_eq!(local_peer_id, id);
    }

    // Add the remote's address info
    match local_sh.add_peer(remote_id, Some(remote_addr)).await.unwrap() {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }

    Setup {
        local_stronghold: local_sh,
        remote_stronghold: remote_sh,
        local_id: local_peer_id,
        remote_id,
        remote_client,
    }
}

#[actix::test]
async fn test_stronghold_p2p() {
    let system = actix::System::current();
    let arbiter = system.arbiter();

    let Setup {
        local_stronghold,
        remote_stronghold,
        remote_id,
        remote_client,
        ..
    } = spawn_peers(FirewallSetup::default(), None).await;
    let remote_client_clone = remote_client.clone();

    // Channel for signaling that local/ remote is ready i.g. performed a necessary write, before the other ran try
    // read.
    let (remote_ready_tx, mut remote_ready_rx) = mpsc::channel(1);
    let (local_ready_tx, mut local_ready_rx) = mpsc::channel(1);

    let key1 = bytestring(1024);
    let data1 = b"some data".to_vec();
    let key1_clone = key1.clone();
    let data1_clone = data1.clone();

    let key2 = bytestring(1024);
    let data2 = b"some second data".to_vec();
    let key2_clone = key2.clone();
    let data2_clone = data2.clone();

    let seed1 = fresh::location();
    let seed1_clone = seed1.clone();

    let (thread_done_tx, mut thread_done_rx) = mpsc::channel(1);
    let thread_done_tx_clone = thread_done_tx.clone();

    let spawned_local = arbiter.spawn(async move {
        remote_ready_rx.recv().await.unwrap();

        // TEST 1: writing at remote and reading it from local stronghold
        let payload = local_stronghold
            .read_from_remote_store(remote_id, remote_client_clone.clone(), key1)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
        assert_eq!(payload.unwrap(), data1);

        // TEST 2: writing from local and reading it at remote
        local_stronghold
            .write_to_remote_store(remote_id, remote_client_clone.clone(), key2, data2, None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));
        local_ready_tx.send(()).await.unwrap();

        // TEST 3: writing and reading from local
        let key3 = bytestring(1024);
        let original_data3 = b"some third data".to_vec();
        local_stronghold
            .write_to_remote_store(
                remote_id,
                remote_client_clone.clone(),
                key3.clone(),
                original_data3.clone(),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

        let payload = local_stronghold
            .read_from_remote_store(remote_id, remote_client_clone.clone(), key3)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));

        assert_eq!(payload.unwrap(), original_data3);

        remote_ready_rx.recv().await.unwrap();

        let (_path, chain) = fresh::hd_path();

        // TEST 4: procedure execution from local
        match local_stronghold
            .remote_runtime_exec(
                remote_id,
                remote_client_clone,
                Slip10Derive {
                    output: fresh::location(),
                    chain,
                    hint: fresh::record_hint(),
                    input: Slip10DeriveInput::Seed(seed1),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("Could not execute remote procedure: {}", e))
        {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        thread_done_tx.send(()).await.unwrap();
    });
    assert!(spawned_local);

    let spawned_remote = arbiter.spawn(async move {
        // TEST 1: writing at remote and reading it from local stronghold
        remote_stronghold
            .write_to_store(key1_clone, data1_clone, None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

        remote_ready_tx.send(()).await.unwrap();
        local_ready_rx.recv().await.unwrap();

        // TEST 2: writing from local and reading it at remote
        let payload = remote_stronghold
            .read_from_store(key2_clone)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
        assert_eq!(payload.unwrap(), data2_clone);

        // TEST 5: procedure execution at remote
        match remote_stronghold
            .runtime_exec(Slip10Generate {
                size_bytes: None,
                output: seed1_clone,
                hint: fresh::record_hint(),
            })
            .await
            .unwrap_or_else(|e| panic!("Could not execute remote procedure: {}", e))
        {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        remote_ready_tx.send(()).await.unwrap();

        thread_done_tx_clone.send(()).await.unwrap();
    });
    assert!(spawned_remote);

    // wait for both threads to return
    thread_done_rx.recv().await.unwrap();
    thread_done_rx.recv().await.unwrap();
}

#[actix::test]
async fn test_p2p_config() {
    let keys_location = fresh::location();
    let Setup {
        mut local_stronghold,
        local_id,
        remote_stronghold,
        remote_id,
        remote_client,
    } = spawn_peers(FirewallSetup::default(), Some(keys_location.clone())).await;

    // Set a firewall rule
    remote_stronghold
        .set_peer_permissions(Permissions::default(), local_id)
        .await
        .unwrap();

    // Test that the firewall rule is effective
    let res = local_stronghold
        .read_from_remote_store(remote_id, remote_client.clone(), bytestring(10))
        .await;
    match res {
        Ok(_) => panic!("Request should be rejected."),
        Err(P2pError::Local(e)) => panic!("Unexpected error {}", e),
        Err(P2pError::SendRequest(OutboundFailure::NotPermitted))
        | Err(P2pError::SendRequest(OutboundFailure::DialFailure))
        | Err(P2pError::SendRequest(OutboundFailure::Shutdown))
        | Err(P2pError::SendRequest(OutboundFailure::Timeout)) => panic!("Unexpected error {:?}", res),
        Err(_) => {}
    }

    // Stop p2p and store the config in the stronghold store.
    // This should persist firewall configuration and the collected address info about the remote.
    let store = bytestring(1024);
    match local_stronghold.stop_p2p(Some(store.clone())).await.unwrap() {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }

    // Spawn p2p again and load the config. Use the same keypair to keep the same peer-id.
    match local_stronghold
        .spawn_p2p_load_config(store, Some(keys_location), None)
        .await
    {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    let SwarmInfo { local_peer_id, .. } = local_stronghold.get_swarm_info().await.unwrap();
    assert_eq!(local_peer_id, local_id);

    // Test if the local peer still has the remote's address info.
    match local_stronghold.add_peer(remote_id, None).await.unwrap() {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    // Test that the firewall rule is still effective
    let res = local_stronghold
        .read_from_remote_store(remote_id, remote_client, bytestring(10))
        .await;
    match res {
        Ok(_) => panic!("Request should be rejected."),
        Err(P2pError::Local(e)) => panic!("Unexpected error {}", e),
        Err(P2pError::SendRequest(OutboundFailure::NotPermitted))
        | Err(P2pError::SendRequest(OutboundFailure::DialFailure))
        | Err(P2pError::SendRequest(OutboundFailure::Shutdown))
        | Err(P2pError::SendRequest(OutboundFailure::Timeout)) => panic!("Unexpected error {:?}", res),
        Err(_) => {}
    }
}

#[actix::test]
async fn test_p2p_firewall() {
    let system = actix::System::current();
    let arbiter = system.arbiter();

    let (firewall_tx, mut firewall_rx) = FirewallChannel::new();

    let Setup {
        local_stronghold,
        local_id,
        mut remote_stronghold,
        remote_id,
        remote_client,
    } = spawn_peers(FirewallSetup::Async(firewall_tx), None).await;

    let forbidden_client_path = fresh::bytestring(1024);
    remote_stronghold
        .spawn_stronghold_actor(forbidden_client_path.clone(), vec![])
        .await
        .unwrap();

    let allowed_client_path = remote_client;
    let allowed_client_path_clone = allowed_client_path.clone();

    let allowed_vault_path = fresh::bytestring(1024);
    let allowed_vault_path_clone = allowed_vault_path.clone();

    let spawned_remote = arbiter.spawn(async move {
        let _ = remote_stronghold;
        // Permissions requests issued by the write attempt of `local_stronghold`.
        let permission_setter = firewall_rx.select_next_some().await;
        assert_eq!(permission_setter.peer(), local_id);

        // Allow `write` only on vault `allowed_vault_path_clone` in client `allowed_client_path_clone`.
        let client_permissions =
            ClientAccess::allow_none().with_vault_access(allowed_vault_path_clone, false, true, false);
        let permissions =
            Permissions::allow_none().with_client_permissions(allowed_client_path_clone, client_permissions);
        permission_setter.set_permissions(permissions).unwrap();
    });
    assert!(spawned_remote);

    let (done_tx, done_rx) = oneshot::channel();
    let spawned_local = actix::System::current().arbiter().spawn(async move {
        let loc1 = Location::generic(allowed_vault_path.clone(), fresh::bytestring(1024));

        let res = local_stronghold
            .write_remote_vault(
                remote_id,
                allowed_client_path.clone(),
                loc1.clone(),
                fresh::bytestring(1024),
                fresh::record_hint(),
                vec![],
            )
            .await
            .map(|ok| ok.unwrap());
        assert!(res.is_ok());

        let res = local_stronghold
            .write_remote_vault(
                remote_id,
                forbidden_client_path.clone(),
                loc1,
                fresh::bytestring(1024),
                fresh::record_hint(),
                vec![],
            )
            .await
            .map(|ok| ok.unwrap());
        // Firewall at the remote rejected the request to the invalid client path.
        assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

        let loc2 = Location::generic(allowed_client_path.clone(), fresh::bytestring(1024));
        let res = local_stronghold
            .write_remote_vault(
                remote_id,
                allowed_client_path.clone(),
                loc2,
                fresh::bytestring(1024),
                fresh::record_hint(),
                vec![],
            )
            .await
            .map(|ok| ok.unwrap());
        // Firewall at the remote rejected the request to the invalid vault path.
        assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

        let loc3 = Location::generic(allowed_vault_path.clone(), fresh::bytestring(1024));
        let proc_generate = Slip10Generate {
            size_bytes: None,
            output: loc3.clone(),
            hint: fresh::record_hint(),
        };

        let loc4 = Location::generic(allowed_vault_path.clone(), fresh::bytestring(1024));
        let proc_derive = Slip10Derive {
            input: Slip10DeriveInput::Seed(loc3),
            chain: fresh::hd_path().1,
            output: loc4,
            hint: fresh::record_hint(),
        };

        let res = local_stronghold
            .remote_runtime_exec_chained(
                remote_id,
                allowed_client_path.clone(),
                vec![proc_generate.into(), proc_derive.into()],
            )
            .await
            .map(|ok| ok.unwrap());
        // Firewall at the remote rejected the request  because only `write` is allowed, but not
        // `use`, which is required for the `Slip10Derive`.
        assert_eq!(res, Err(P2pError::SendRequest(OutboundFailure::ConnectionClosed)));

        // Counter check that Slip10Generate on its own works.
        let loc5 = Location::generic(allowed_vault_path.clone(), fresh::bytestring(1024));
        let proc_generate = Slip10Generate {
            size_bytes: None,
            output: loc5,
            hint: fresh::record_hint(),
        };
        let res = local_stronghold
            .remote_runtime_exec(remote_id, allowed_client_path.clone(), proc_generate)
            .await
            .map(|ok| ok.unwrap());
        assert!(res.is_ok());

        done_tx.send(()).unwrap()
    });
    assert!(spawned_local);

    done_rx.await.unwrap();
}

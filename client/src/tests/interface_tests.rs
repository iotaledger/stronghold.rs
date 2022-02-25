// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ActorError, Location, RecordHint, Stronghold};
use stronghold_utils::random::bytestring;

#[cfg(feature = "p2p")]
use crate::{
    p2p::{identity::Keypair, NetworkConfig, PeerId, SwarmInfo},
    procedures::{Slip10Derive, Slip10DeriveInput, Slip10Generate},
    tests::fresh,
};
#[cfg(feature = "p2p")]
use tokio::sync::{mpsc, oneshot};

#[actix::test]
async fn test_stronghold() {
    let vault_path = b"path".to_vec();
    let client_path = b"test".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);
    let loc1 = Location::counter::<_, usize>("path", 1);
    let loc2 = Location::counter::<_, usize>("path", 2);

    let store_loc = bytestring(4096);

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    // clone it, and check for consistency
    let stronghold2 = stronghold.clone();

    // Write at the first record of the vault using Some(0).  Also creates the new vault.
    assert!(stronghold2
        .write_to_vault(
            loc0.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold2
        .read_secret(client_path.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // read head from first reference
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(stronghold
        .write_to_vault(
            loc1.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"another hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold.read_secret(client_path.clone(), loc1.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(stronghold
        .write_to_vault(
            loc2.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"yet another hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    // Read the first record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Read the head record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc1).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = stronghold.list_hints_and_ids(vault_path.clone()).await.unwrap();
    println!("{:?}", ids);

    stronghold
        .delete_data(loc0.clone(), true)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap();

    // attempt to read the first record of the vault.
    let p = stronghold.read_secret(client_path.clone(), loc0.clone()).await.unwrap();

    assert!(p.is_none());

    let ids = stronghold.list_hints_and_ids(vault_path.clone()).await.unwrap();
    println!("{:?}", ids);

    stronghold
        .write_to_store(store_loc.clone(), b"test".to_vec(), None)
        .await
        .unwrap();

    let data = stronghold.read_from_store(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    stronghold.garbage_collect(vault_path).await.unwrap();

    stronghold
        .write_all_to_snapshot(&key_data, Some("test0".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold
        .read_snapshot(client_path.clone(), None, &key_data, Some("test0".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // read head after reading snapshot.

    let p = stronghold.read_secret(client_path.clone(), loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let p = stronghold.read_secret(client_path.clone(), loc0).await.unwrap();

    assert!(p.is_none());

    stronghold.kill_stronghold(client_path.clone(), false).await.unwrap();

    let p = stronghold.read_secret(client_path.clone(), loc2).await.unwrap();

    assert!(p.is_none());

    let data = stronghold.read_from_store(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    stronghold.delete_from_store(store_loc.clone()).await.unwrap();

    let data = stronghold.read_from_store(store_loc).await.unwrap();

    assert!(data.is_none());

    stronghold.kill_stronghold(client_path.clone(), true).await.unwrap();

    assert!(matches!(
        stronghold.switch_actor_target(client_path).await,
        Err(ActorError::TargetNotFound)
    ))
}

#[actix::test]
async fn run_stronghold_multi_actors() {
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path0 = b"test a".to_vec();
    let client_path1 = b"test b".to_vec();
    let client_path2 = b"test c".to_vec();
    let client_path3 = b"test d".to_vec();

    let loc0 = Location::counter::<_, usize>("path", 0);

    let loc2 = Location::counter::<_, usize>("path", 2);
    let loc3 = Location::counter::<_, usize>("path", 3);
    let loc4 = Location::counter::<_, usize>("path", 4);

    let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .spawn_stronghold_actor(client_path1.clone(), vec![])
        .await
        .unwrap();

    stronghold.switch_actor_target(client_path0.clone()).await.unwrap();

    assert!(stronghold
        .write_to_vault(loc0.clone(), b"test".to_vec(), RecordHint::new(b"0").unwrap(), vec![],)
        .await
        .is_ok());

    // read head.
    let p = stronghold
        .read_secret(client_path0.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    stronghold.switch_actor_target(client_path1.clone()).await.unwrap();

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(stronghold
        .write_to_vault(
            loc0.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"1").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    // read head.
    let p = stronghold
        .read_secret(client_path1.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    stronghold.switch_actor_target(client_path0.clone()).await.unwrap();

    assert!(stronghold
        .write_to_vault(
            loc0.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"2").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold
        .read_secret(client_path0.clone(), loc0.clone())
        .await
        .unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = stronghold.list_hints_and_ids(loc2.vault_path()).await.unwrap();
    println!("actor 0: {:?}", ids);

    stronghold
        .write_all_to_snapshot(&key_data.to_vec(), Some("megasnap".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    stronghold.switch_actor_target(client_path1.clone()).await.unwrap();

    let ids = stronghold.list_hints_and_ids(loc2.vault_path()).await.unwrap();
    println!("actor 1: {:?}", ids);

    stronghold
        .spawn_stronghold_actor(client_path2.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .read_snapshot(
            client_path2.clone(),
            Some(client_path1.clone()),
            &key_data,
            Some("megasnap".into()),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // client_path2 correct?
    let p = stronghold.read_secret(client_path2.clone(), loc0).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(stronghold
        .write_to_vault(
            loc3.clone(),
            b"a new actor test".to_vec(),
            RecordHint::new(b"2").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold.read_secret(client_path2.clone(), loc3).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

    assert!(stronghold
        .write_to_vault(
            loc4.clone(),
            b"a new actor test again".to_vec(),
            RecordHint::new(b"3").unwrap(),
            vec![],
        )
        .await
        .is_ok());

    let p = stronghold.read_secret(client_path2, loc4.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

    let mut ids2 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();

    stronghold.switch_actor_target(client_path1).await.unwrap();

    let mut ids1 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    ids2.sort();
    ids1.sort();

    println!("ids and hints => actor 1: {:?}", ids1);
    println!("ids and hints => actor 2: {:?}", ids2);

    assert_eq!(ids1, ids2);

    stronghold
        .spawn_stronghold_actor(client_path3.clone(), vec![])
        .await
        .unwrap();

    stronghold
        .read_snapshot(
            client_path3,
            Some(client_path0.clone()),
            &key_data,
            Some("megasnap".into()),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    let mut ids3 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    println!("actor 3: {:?}", ids3);

    stronghold.switch_actor_target(client_path0).await.unwrap();

    let mut ids0 = stronghold.list_hints_and_ids(loc4.vault_path()).await.unwrap();
    println!("actor 0: {:?}", ids0);

    ids0.sort();
    ids3.sort();

    assert_eq!(ids0, ids3);

    // stronghold.system.print_tree();
}

#[actix::test]
async fn test_stronghold_generics() {
    // let sys = ActorSystem::new().unwrap();
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path = b"test a".to_vec();

    let slip10_seed = Location::generic("slip10", "seed");

    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();

    assert!(stronghold
        .write_to_vault(
            slip10_seed.clone(),
            b"AAAAAA".to_vec(),
            RecordHint::new(b"first hint").unwrap(),
            vec![],
        )
        .await
        .is_ok());
    let p = stronghold.read_secret(client_path, slip10_seed).await.unwrap();
    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("AAAAAA"));

    stronghold
        .write_all_to_snapshot(&key_data.to_vec(), Some("generic".into()), None)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));
}

#[cfg(feature = "p2p")]
#[actix::test]
async fn test_stronghold_p2p() {
    let system = actix::System::current();
    let arbiter = system.arbiter();

    let (addr_tx, addr_rx) = oneshot::channel();

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

    let (res_tx, mut res_rx) = mpsc::channel(1);
    let res_tx_clone = res_tx.clone();

    let remote_client = b"remote".to_vec();
    let remote_client_clone = remote_client.clone();

    let spawned_local = arbiter.spawn(async move {
        let local_client = b"local".to_vec();
        let mut local_stronghold = Stronghold::init_stronghold_system(local_client, vec![])
            .await
            .unwrap_or_else(|e| panic!("Could not create a stronghold instance: {}", e));
        local_stronghold
            .spawn_p2p(NetworkConfig::default(), None)
            .await
            .unwrap_or_else(|e| panic!("Could not spawn p2p: {}", e));

        let (peer_id, addr) = addr_rx.await.unwrap();
        local_stronghold
            .add_peer(peer_id, Some(addr))
            .await
            .unwrap_or_else(|e| panic!("Actor error: {}", e))
            .unwrap_or_else(|e| panic!("Could not establish connection to remote: {}", e));

        remote_ready_rx.recv().await.unwrap();

        // test writing at remote and reading it from local stronghold
        let payload = local_stronghold
            .read_from_remote_store(peer_id, remote_client_clone.clone(), key1)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
        assert_eq!(payload.unwrap(), data1);

        // test writing from local and reading it at remote
        local_stronghold
            .write_to_remote_store(peer_id, remote_client_clone.clone(), key2, data2, None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));
        local_ready_tx.send(()).await.unwrap();

        // test writing and reading from local
        let key3 = bytestring(1024);
        let original_data3 = b"some third data".to_vec();
        local_stronghold
            .write_to_remote_store(
                peer_id,
                remote_client_clone.clone(),
                key3.clone(),
                original_data3.clone(),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

        let payload = local_stronghold
            .read_from_remote_store(peer_id, remote_client_clone.clone(), key3)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));

        assert_eq!(payload.unwrap(), original_data3);

        remote_ready_rx.recv().await.unwrap();

        let (_path, chain) = fresh::hd_path();

        match local_stronghold
            .remote_runtime_exec(
                peer_id,
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
        res_tx.send(()).await.unwrap();
    });
    assert!(spawned_local);

    let spawned_remote = arbiter.spawn(async move {
        let mut remote_stronghold = Stronghold::init_stronghold_system(remote_client, vec![])
            .await
            .unwrap_or_else(|e| panic!("Could not create a stronghold instance: {}", e));
        remote_stronghold
            .spawn_p2p(NetworkConfig::default(), None)
            .await
            .unwrap_or_else(|e| panic!("Could not create a stronghold instance: {}", e));

        let addr = remote_stronghold
            .start_listening(None)
            .await
            .unwrap_or_else(|e| panic!("Actor error: {}", e))
            .unwrap_or_else(|e| panic!("Could not start listening: {}", e));

        let swarm_info = remote_stronghold
            .get_swarm_info()
            .await
            .unwrap_or_else(|e| panic!("Could not get swarm info: {}", e));

        assert!(swarm_info.listeners.into_iter().any(|l| l.addrs.contains(&addr)));
        addr_tx.send((swarm_info.local_peer_id, addr)).unwrap();
        // test writing at remote and reading it from local stronghold
        remote_stronghold
            .write_to_store(key1_clone, data1_clone, None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

        remote_ready_tx.send(()).await.unwrap();
        local_ready_rx.recv().await.unwrap();

        // test writing from local and reading it at remoteom local and reading it at remote
        let payload = remote_stronghold
            .read_from_store(key2_clone)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
        assert_eq!(payload.unwrap(), data2_clone);

        // test procedure execution
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
        res_tx_clone.send(()).await.unwrap();
    });
    assert!(spawned_remote);

    // wait for both threads to return
    res_rx.recv().await.unwrap();
    res_rx.recv().await.unwrap();
}

#[cfg(feature = "p2p")]
#[actix::test]
async fn test_p2p_config() {
    use p2p::{firewall::Rule, OutboundFailure};

    use crate::p2p::P2pError;

    let remote_client = bytestring(4096);
    // Start remote stronghold and start listening
    let mut remote_sh = Stronghold::init_stronghold_system(remote_client.clone(), vec![])
        .await
        .unwrap();
    match remote_sh
        .spawn_p2p(NetworkConfig::default().with_mdns_enabled(false), None)
        .await
    {
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

    // Start (local) stronghold.
    let client_path = fresh::bytestring(4096);
    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap();
    // Generate a new Keypair and write it to the vault
    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from_public_key(&keypair.public());
    let keys_location = fresh::location();
    match stronghold
        .write_p2p_keypair(keypair, keys_location.clone(), fresh::record_hint())
        .await
        .unwrap()
    {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    // Spawn p2p that uses the new keypair
    match stronghold
        .spawn_p2p(
            NetworkConfig::default().with_mdns_enabled(false),
            Some(keys_location.clone()),
        )
        .await
    {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }

    // Start listening
    let addr = match stronghold.start_listening(None).await.unwrap() {
        Ok(addr) => addr,
        Err(e) => panic!("Unexpected error {}", e),
    };
    let SwarmInfo {
        local_peer_id,
        listeners,
        ..
    } = stronghold.get_swarm_info().await.unwrap();
    assert_eq!(local_peer_id, peer_id);
    assert!(listeners.first().unwrap().addrs.contains(&addr));
    // Set a firewall rule
    stronghold
        .set_firewall_rule(Rule::RejectAll, vec![remote_id], false)
        .await
        .unwrap();
    // Add the remote's address info
    match stronghold.add_peer(remote_id, Some(remote_addr.clone())).await.unwrap() {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    // Test that the firewall rule is effective
    let res = remote_sh
        .read_from_remote_store(peer_id, remote_client.clone(), bytestring(10))
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
    match stronghold.stop_p2p(Some(store.clone())).await.unwrap() {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }

    // Spawn p2p again and load the config. Use the same keypair to keep the same peer-id.
    match stronghold.spawn_p2p_load_config(store, Some(keys_location)).await {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    let SwarmInfo { local_peer_id, .. } = stronghold.get_swarm_info().await.unwrap();

    // Test if the local peer still has the remote's address info.
    assert_eq!(local_peer_id, peer_id);
    match stronghold.add_peer(remote_id, None).await.unwrap() {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error {}", e),
    }
    // Test that the firewall rule is still effective
    let res = remote_sh
        .read_from_remote_store(peer_id, remote_client, bytestring(10))
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

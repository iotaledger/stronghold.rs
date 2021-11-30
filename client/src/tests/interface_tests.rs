// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "p2p")]
use crate::{
    actors::NetworkConfig,
    p2p::{identity::Keypair, PeerId, SwarmInfo},
    procedures::{PersistSecret, Slip10Derive, Slip10Generate},
};
use crate::{
    interface::{Client, Snapshot, Store, Vault, VaultLocation},
    tests::fresh,
    RecordHint, SnapshotFile, Stronghold,
};
use std::path::PathBuf;
use stronghold_utils::random::bytestring;
#[cfg(feature = "p2p")]
use tokio::sync::{mpsc, oneshot};

#[actix::test]
async fn stronghold_interface_example() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = b"vault".to_vec();
    let client_path = b"client";
    let key_data = [0xff; 32].to_vec();
    let file = SnapshotFile::named("testfile");

    let record_location = VaultLocation::counter(0);

    let store_loc = bytestring(4096);

    let mut snapshot: Snapshot = Snapshot::new(file.clone());
    let client: Client = snapshot.client(client_path).await?;
    let vault: Vault = client.vault(vault_path.clone());
    let store: Store = client.store();

    vault
        .write(
            record_location.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").unwrap(),
        )
        .await??;

    store.write(store_loc.clone(), b"test".to_vec(), None).await?;

    snapshot.write(&key_data).await??;

    std::mem::drop(client);
    std::mem::drop(snapshot);

    let mut snapshot = Snapshot::new(file.clone());
    snapshot.read(&key_data).await??;

    let client: Client = snapshot.client(client_path).await?;
    client.restore_state().await?;

    let store_data = client.store().read(store_loc.clone()).await?.unwrap();
    let vault_data = client
        .vault(vault_path)
        .read_secret(record_location.clone())
        .await?
        .unwrap();

    assert_eq!(store_data, b"test");
    assert_eq!(vault_data, b"test");

    Ok(())
}

#[actix::test]
async fn test_stronghold_x() {
    let vault_path = b"path".to_vec();
    let client_path = b"test";

    let loc0 = VaultLocation::counter(0);
    let loc1 = VaultLocation::counter(1);
    let loc2 = VaultLocation::counter(2);

    let store_loc = bytestring(4096);

    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let mut snapshot = Snapshot::new(SnapshotFile::named("test0"));

    let client: Client = snapshot.client(client_path).await.unwrap();
    let vault: Vault = client.vault(vault_path);
    let store: Store = client.store();

    // clone it, and check for consistency
    // let stronghold2 = stronghold.clone();

    // Write at the first record of the vault using Some(0).  Also creates the new vault.
    assert!(vault
        .write(loc0.clone(), b"test".to_vec(), RecordHint::new(b"first hint").unwrap(),)
        .await
        .is_ok());

    // read head.
    let p = vault.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // read head from first reference
    let p = vault.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(vault
        .write(
            loc1.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"another hint").unwrap(),
        )
        .await
        .is_ok());

    // read head.
    let p = vault.read_secret(loc1.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(vault
        .write(
            loc2.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"yet another hint").unwrap(),
        )
        .await
        .is_ok());

    // read head.
    let p = vault.read_secret(loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    // Read the first record of the vault.
    let p = vault.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // Read the head record of the vault.
    let p = vault.read_secret(loc1).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    let p = vault.read_secret(loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = vault.list().await.unwrap();
    println!("{:?}", ids);

    vault
        .revoke(loc0.clone(), true)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap();

    // attempt to read the first record of the vault.
    let p = vault.read_secret(loc0.clone()).await.unwrap();

    assert!(p.is_none());

    let ids = vault.list().await.unwrap();
    println!("{:?}", ids);

    store.write(store_loc.clone(), b"test".to_vec(), None).await.unwrap();

    let data = store.read(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    vault.collect_garbage().await.unwrap();

    snapshot
        .write(&key_data)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    snapshot
        .read(&key_data)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // read head after reading snapshot.

    let p = vault.read_secret(loc2.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let p = vault.read_secret(loc0).await.unwrap();

    assert!(p.is_none());

    let data = store.read(store_loc.clone()).await.unwrap().unwrap();

    assert_eq!(std::str::from_utf8(&data), Ok("test"));

    store.delete(store_loc.clone()).await.unwrap();

    let data = store.read(store_loc).await.unwrap();

    assert!(data.is_none());
}

#[cfg(feature = "p2p")]
#[actix::test]
async fn stronghold_discard_inactive_clients() {
    let password = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
    let path: PathBuf = "./strong.hodl".into();

    let client_path0 = b"test a";
    let client_path1 = b"test b";

    let vault_path0: &[u8] = b"123";
    let vault_path1: &[u8] = b"456";
    {
        let mut snapshot = Snapshot::new(path.clone());
        {
            let client0 = snapshot.client(client_path0).await.unwrap();
            let client1 = snapshot.client(client_path1).await.unwrap();

            client0
                .vault(vault_path0)
                .write(
                    VaultLocation::generic(b"".to_vec()),
                    b"test test".to_vec(),
                    RecordHint::new("123").unwrap(),
                )
                .await
                .unwrap()
                .unwrap();

            client1
                .vault(vault_path1)
                .write(
                    VaultLocation::generic(b"".to_vec()),
                    b"foo bar".to_vec(),
                    RecordHint::new("456").unwrap(),
                )
                .await
                .unwrap()
                .unwrap();

            assert!(client0.vault(vault_path0).exists().await.unwrap());
            assert!(client1.vault(vault_path1).exists().await.unwrap());
        } // <-- clients are dropped here, removing their references to their respective actors.

        snapshot.write(&password).await.unwrap().unwrap();
    }

    let mut snapshot = Snapshot::new(path.clone());

    snapshot.read(&password).await.unwrap().unwrap();

    let client0 = snapshot.client(client_path0).await.unwrap();
    let client1 = snapshot.client(client_path1).await.unwrap();

    // State is not loaded into actors; expect vaults to *not* exist.
    assert!(!client0.vault(vault_path0).exists().await.unwrap());
    assert!(!client1.vault(vault_path1).exists().await.unwrap());

    client0.restore_state().await.unwrap();
    client1.restore_state().await.unwrap();

    assert!(client0.vault(vault_path0).exists().await.unwrap());
    assert!(client1.vault(vault_path1).exists().await.unwrap());

    std::fs::remove_file(path).unwrap();
}

#[actix::test]
async fn run_stronghold_multi_actors() {
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let file = SnapshotFile::named("megasnap");
    let client_path0 = b"test a";
    let client_path1 = b"test b";
    // let client_path2 = b"test c".to_vec();
    // let client_path3 = b"test d".to_vec();

    let vault_path = b"path".to_vec();

    let loc0 = VaultLocation::counter(0);
    // let loc2 = VaultLocation::counter(2);
    let loc3 = VaultLocation::counter(3);
    let loc4 = VaultLocation::counter(4);

    let mut snapshot = Snapshot::new(file.clone());

    let client0: Client = snapshot.client(client_path0).await.unwrap();
    let vault0: Vault = client0.vault(vault_path.clone());

    assert!(vault0
        .write(loc0.clone(), b"test".to_vec(), RecordHint::new(b"0").unwrap())
        .await
        .is_ok());

    // read head.
    let p = vault0.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

    // stronghold.switch_actor_target(client_path1.clone()).await.unwrap();

    let client1: Client = snapshot.client(client_path1).await.unwrap();
    let vault1: Vault = client1.vault(vault_path.clone());

    // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
    assert!(vault1
        .write(loc0.clone(), b"another test".to_vec(), RecordHint::new(b"1").unwrap())
        .await
        .is_ok());

    // read head.
    let p = vault1.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    // stronghold.switch_actor_target(client_path0.clone()).await.unwrap();

    assert!(vault0
        .write(
            loc0.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"2").unwrap()
        )
        .await
        .is_ok());

    let p = vault0.read_secret(loc0.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

    let ids = vault0.list().await.unwrap();
    println!("actor 0: {:?}", ids);

    snapshot
        .write(&key_data.to_vec())
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Write snapshot error: {}", e));

    let ids = vault1.list().await.unwrap();
    println!("actor 1: {:?}", ids);

    snapshot
        .read(&key_data)
        .await
        .unwrap_or_else(|e| panic!("Actor error: {}", e))
        .unwrap_or_else(|e| panic!("Read snapshot error: {}", e));

    // To mimic the read_snapshot with former_client_id we clone the client,
    // since that is closest to what's effectively happening in the previous interface.
    let client2 = client1.clone();
    let vault2: Vault = client2.vault(vault_path.clone());

    let p = vault2.read_secret(loc0).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

    assert!(vault2
        .write(
            loc3.clone(),
            b"a new actor test".to_vec(),
            RecordHint::new(b"2").unwrap()
        )
        .await
        .is_ok());

    let p = vault2.read_secret(loc3).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

    assert!(vault2
        .write(
            loc4.clone(),
            b"a new actor test again".to_vec(),
            RecordHint::new(b"3").unwrap()
        )
        .await
        .is_ok());

    let p = vault2.read_secret(loc4.clone()).await.unwrap();

    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

    let mut ids2 = vault2.list().await.unwrap();
    let mut ids1 = vault1.list().await.unwrap();

    ids2.sort();
    ids1.sort();

    println!("ids and hints => actor 1: {:?}", ids1);
    println!("ids and hints => actor 2: {:?}", ids2);

    assert_eq!(ids1, ids2);

    let client3 = client0.clone();
    let vault3: Vault = client3.vault(vault_path);

    let mut ids3 = vault3.list().await.unwrap();
    println!("actor 3: {:?}", ids3);

    let mut ids0 = vault0.list().await.unwrap();
    println!("actor 0: {:?}", ids0);

    ids0.sort();
    ids3.sort();

    assert_eq!(ids0, ids3);
}

#[actix::test]
async fn test_stronghold_generics() {
    let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

    let client_path = b"test a".to_vec();
    let seed_location = VaultLocation::generic("seed");

    let mut snapshot = Snapshot::new(SnapshotFile::named("generic"));

    let client0: Client = snapshot.client(&client_path).await.unwrap();
    let vault0: Vault = client0.vault("slip10");

    assert!(vault0
        .write(
            seed_location.clone(),
            b"AAAAAA".to_vec(),
            RecordHint::new(b"first hint").unwrap()
        )
        .await
        .is_ok());

    let p = vault0.read_secret(seed_location).await.unwrap();
    assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("AAAAAA"));

    snapshot
        .write(&key_data.to_vec())
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
            .read_from_remote_store(peer_id, key1)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));
        assert_eq!(payload.unwrap(), data1);

        // test writing from local and reading it at remote
        local_stronghold
            .write_to_remote_store(peer_id, key2, data2, None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));
        local_ready_tx.send(()).await.unwrap();

        // test writing and reading from local
        let key3 = bytestring(1024);
        let original_data3 = b"some third data".to_vec();
        local_stronghold
            .write_to_remote_store(peer_id, key3.clone(), original_data3.clone(), None)
            .await
            .unwrap_or_else(|e| panic!("Could not write to remote store: {}", e));

        let payload = local_stronghold
            .read_from_remote_store(peer_id, key3)
            .await
            .unwrap_or_else(|e| panic!("Could not read from remote store: {}", e));

        assert_eq!(payload.unwrap(), original_data3);

        remote_ready_rx.recv().await.unwrap();

        let (_path, chain) = fresh::hd_path();

        match local_stronghold
            .remote_runtime_exec(peer_id, Slip10Derive::new_from_seed(seed1, chain))
            .await
            .unwrap_or_else(|e| panic!("Could not execute remote procedure: {}", e))
        {
            Ok(out) => assert!(out.into_iter().next().is_none()),
            Err(e) => panic!("unexpected error: {:?}", e),
        };
        res_tx.send(()).await.unwrap();
    });
    assert!(spawned_local);

    let spawned_remote = arbiter.spawn(async move {
        let remote_client = b"remote".to_vec();
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
            .runtime_exec(Slip10Generate::default().write_secret(seed1_clone, fresh::record_hint()))
            .await
            .unwrap_or_else(|e| panic!("Could not execute remote procedure: {}", e))
        {
            Ok(out) => assert!(out.into_iter().next().is_none()),
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

    // Start remote stronghold and start listening
    let mut remote_sh = Stronghold::init_stronghold_system(bytestring(4096), vec![])
        .await
        .unwrap();
    match remote_sh
        .spawn_p2p(NetworkConfig::default().with_mdns_enabled(false), None)
        .await
    {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }
    let remote_addr = match remote_sh.start_listening(None).await.unwrap() {
        Ok(a) => a,
        Err(e) => panic!("Unexpected error {}", e.to_string()),
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
        Err(e) => panic!("Unexpected error {}", e.to_string()),
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
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }

    // Start listening
    let addr = match stronghold.start_listening(None).await.unwrap() {
        Ok(addr) => addr,
        Err(e) => panic!("Unexpected error {}", e.to_string()),
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
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }
    // Test that the firewall rule is effective
    let res = remote_sh.read_from_remote_store(peer_id, bytestring(10)).await;
    match res {
        Ok(_) => panic!("Request should be rejected."),
        Err(P2pError::Local(e)) => panic!("Unexpected error {}", e.to_string()),
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
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }

    // Spawn p2p again and load the config. Use the same keypair to keep the same peer-id.
    match stronghold.spawn_p2p_load_config(store, Some(keys_location)).await {
        Ok(()) => {}
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }
    let SwarmInfo { local_peer_id, .. } = stronghold.get_swarm_info().await.unwrap();

    // Test if the local peer still has the remote's address info.
    assert_eq!(local_peer_id, peer_id);
    match stronghold.add_peer(remote_id, None).await.unwrap() {
        Ok(_) => {}
        Err(e) => panic!("Unexpected error {}", e.to_string()),
    }
    // Test that the firewall rule is still effective
    let res = remote_sh.read_from_remote_store(peer_id, bytestring(10)).await;
    match res {
        Ok(_) => panic!("Request should be rejected."),
        Err(P2pError::Local(e)) => panic!("Unexpected error {}", e.to_string()),
        Err(P2pError::SendRequest(OutboundFailure::NotPermitted))
        | Err(P2pError::SendRequest(OutboundFailure::DialFailure))
        | Err(P2pError::SendRequest(OutboundFailure::Shutdown))
        | Err(P2pError::SendRequest(OutboundFailure::Timeout)) => panic!("Unexpected error {:?}", res),
        Err(_) => {}
    }
}

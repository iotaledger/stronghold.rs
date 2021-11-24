// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{actors::SnapshotConfig, utils::LoadFromPath, Location, RecordHint, Stronghold};
use engine::vault::ClientId;

#[cfg(feature = "p2p")]
pub use network::*;

#[cfg(feature = "p2p")]
pub mod network {
    use crate::Stronghold;

    #[actix::test]
    #[allow(unused_variables)]
    async fn test_full_synchronization_remote() {
        let system = actix::System::current();
        let arbiter = system.arbiter();

        arbiter.spawn(async move {});

        let a_stronghold = Stronghold::init_stronghold_system(b"client_abc".to_vec(), vec![]);
    }

    #[actix::test]
    async fn test_partial_synchronization_remote() {}

    #[actix::test]
    async fn test_complementary_synchronization_remote() {}
}

#[actix::test]
async fn test_fully_synchronize_snapshot() {
    // __setup

    // A
    let client_path0 = b"client_path0".to_vec();
    let client_path1 = b"client_path1".to_vec();
    let client_path2 = b"client_path2".to_vec();
    let client_path3 = b"client_path3".to_vec();

    // B
    let client_path4 = b"client_path4".to_vec();
    let client_path5 = b"client_path5".to_vec();

    // locations A
    let loc_a0 = Location::Generic {
        record_path: b"loc_a0".to_vec(),
        vault_path: b"vault_a0".to_vec(),
    };
    let loc_a1 = Location::Generic {
        record_path: b"loc_a1".to_vec(),
        vault_path: b"vault_a1".to_vec(),
    };
    let loc_a2 = Location::Generic {
        record_path: b"loc_a2".to_vec(),
        vault_path: b"vault_a2".to_vec(),
    };
    let loc_a3 = Location::Generic {
        record_path: b"loc_a3".to_vec(),
        vault_path: b"vault_a3".to_vec(),
    };

    // locations B
    let loc_b0 = Location::Generic {
        record_path: b"loc_b0".to_vec(),
        vault_path: b"vault_b0".to_vec(),
    };
    let loc_b1 = Location::Generic {
        record_path: b"loc_b1".to_vec(),
        vault_path: b"vault_b1".to_vec(),
    };

    // path A
    let mut tf = std::env::temp_dir();
    tf.push("path_a.snapshot");
    let storage_path_a = tf.to_str().unwrap();

    // path B
    let mut tf = std::env::temp_dir();
    tf.push("path_b.snapshot");
    let storage_path_b = tf.to_str().unwrap();

    // path destination
    let mut tf = std::env::temp_dir();
    tf.push("path_destination.snapshot");
    let storage_path_destination = tf.to_str().unwrap();

    // key for snapshot a
    let key_a = b"aaaBBcDDDDcccbbbBBDDD11223344556".to_vec();

    // key for snapshot b
    let key_b = b"lkjhbhnushfzghfjdkslaksjdnfjs2ks".to_vec();

    // key for destination snapshot
    let key_destination = b"12345678912345678912345678912345".to_vec();

    // __execution
    {
        // A
        let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
            .await
            .unwrap();

        // write into vault for a
        stronghold
            .write_to_vault(
                loc_a0.clone(),
                b"payload_a0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path1.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path1.clone()).await;
        stronghold
            .write_to_vault(
                loc_a1.clone(),
                b"payload_a1".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path2.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path2.clone()).await;
        stronghold
            .write_to_vault(
                loc_a2.clone(),
                b"payload_a2".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path3.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path3.clone()).await;
        stronghold
            .write_to_vault(
                loc_a3.clone(),
                b"payload_a3".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        // write local snapshot
        stronghold
            .write_all_to_snapshot(&key_a, None, Some(storage_path_a.into()))
            .await;
    }

    {
        // B

        // write snapshot b
        let mut stronghold = Stronghold::init_stronghold_system(client_path4.clone(), vec![])
            .await
            .unwrap();

        stronghold
            .write_to_vault(
                loc_b0.clone(),
                b"payload_a0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path5.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path5.clone()).await;
        stronghold
            .write_to_vault(
                loc_b1.clone(),
                b"payload_a0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .write_all_to_snapshot(&key_b, None, Some(storage_path_b.into()))
            .await;
    }

    // load A, partially synchronize with B, test partial entries from A and B
    let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
        .await
        .unwrap();

    // reload A
    let all_paths = vec![
        client_path0.clone(),
        client_path1.clone(),
        client_path2.clone(),
        client_path3.clone(),
    ];

    let former = client_path0.clone();

    // keep the reference to the current client id
    // synchronize the other client_path with this snapshot
    for client_path in all_paths {
        stronghold
            .read_snapshot(
                client_path.clone(),
                Some(former.clone()),
                &key_a,
                None,
                Some(storage_path_a.into()),
            )
            .await;
    }

    let mut key_a_static = [0u8; 32];
    key_a_static.clone_from_slice(&key_a);

    let mut key_b_static = [0u8; 32];
    key_b_static.clone_from_slice(&key_b);

    let mut key_destination_static = [0u8; 32];
    key_destination_static.clone_from_slice(&key_destination);

    // partially synchronize with other snapshot
    stronghold
        .synchronize_local_full(
            ClientId::load_from_path(&client_path0.clone(), &client_path0.clone()).unwrap(),
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_a.into()),
                key: key_a_static,
                generates_output: false,
            },
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_b.into()),
                key: key_b_static,
                generates_output: false,
            },
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_destination.into()),
                key: key_destination_static,
                generates_output: false,
            },
        )
        .await;

    // check for existing locations
    assert!(stronghold.vault_exists(loc_a0).await);
    assert!(stronghold.vault_exists(loc_a1).await);
    assert!(stronghold.vault_exists(loc_a2).await);
    assert!(stronghold.vault_exists(loc_a3).await);
    assert!(stronghold.vault_exists(loc_b0).await);
    assert!(stronghold.vault_exists(loc_b1).await);
}

#[actix::test]
async fn test_partially_synchronize_snapshot() {
    // __setup

    // A
    let client_path0 = b"client_path0".to_vec();
    let client_path1 = b"client_path1".to_vec();
    let client_path2 = b"client_path2".to_vec();
    let client_path3 = b"client_path3".to_vec();

    // B
    let client_path4 = b"client_path4".to_vec();
    let client_path5 = b"client_path5".to_vec();

    // locations A
    let loc_a0 = Location::Generic {
        record_path: b"loc_a0".to_vec(),
        vault_path: b"vault_a0".to_vec(),
    };
    let loc_a1 = Location::Generic {
        record_path: b"loc_a1".to_vec(),
        vault_path: b"vault_a1".to_vec(),
    };
    let loc_a2 = Location::Generic {
        record_path: b"loc_a2".to_vec(),
        vault_path: b"vault_a2".to_vec(),
    };
    let loc_a3 = Location::Generic {
        record_path: b"loc_a3".to_vec(),
        vault_path: b"vault_a3".to_vec(),
    };

    // locations B
    let loc_b0 = Location::Generic {
        record_path: b"loc_b0".to_vec(),
        vault_path: b"vault_b0".to_vec(),
    };
    let loc_b1 = Location::Generic {
        record_path: b"loc_b1".to_vec(),
        vault_path: b"vault_b1".to_vec(),
    };

    // allowed entries from B
    let allowed = vec![ClientId::load_from_path(&client_path5.clone(), &client_path5.clone()).unwrap()];

    // path A
    let mut tf = std::env::temp_dir();
    tf.push("path_a.snapshot");
    let storage_path_a = tf.to_str().unwrap();

    // path B
    let mut tf = std::env::temp_dir();
    tf.push("path_b.snapshot");
    let storage_path_b = tf.to_str().unwrap();

    // path destination
    let mut tf = std::env::temp_dir();
    tf.push("path_destination.snapshot");
    let storage_path_destination = tf.to_str().unwrap();

    // key for snapshot a
    let key_a = b"aaaBBcDDDDcccbbbBBDDD11223344556".to_vec();

    // key for snapshot b
    let key_b = b"lkjhbhnushfzghfjdkslaksjdnfjs2ks".to_vec();

    // key for destination snapshot
    let key_destination = b"12345678912345678912345678912345".to_vec();

    // __execution
    {
        // A
        let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
            .await
            .unwrap();

        // write into vault for a
        stronghold
            .write_to_vault(
                loc_a0.clone(),
                b"payload_a0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path1.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path1.clone()).await;
        stronghold
            .write_to_vault(
                loc_a1.clone(),
                b"payload_a1".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path2.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path2.clone()).await;
        stronghold
            .write_to_vault(
                loc_a2.clone(),
                b"payload_a2".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path3.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path3.clone()).await;
        stronghold
            .write_to_vault(
                loc_a3.clone(),
                b"payload_a3".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        // write local snapshot
        stronghold
            .write_all_to_snapshot(&key_a, None, Some(storage_path_a.into()))
            .await;
    }

    {
        // B

        // write snapshot b
        let mut stronghold = Stronghold::init_stronghold_system(client_path4.clone(), vec![])
            .await
            .unwrap();

        stronghold
            .write_to_vault(
                loc_b0.clone(),
                b"payload_b0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .spawn_stronghold_actor(client_path5.clone(), Vec::new())
            .await;
        stronghold.switch_actor_target(client_path5.clone()).await;
        stronghold
            .write_to_vault(
                loc_b1.clone(),
                b"payload_b0".to_vec(),
                RecordHint::new(b"record_hint_a0".to_vec()).unwrap(),
                vec![],
            )
            .await;

        stronghold
            .write_all_to_snapshot(&key_b, None, Some(storage_path_b.into()))
            .await;
    }

    // load A, partially synchronize with B, test partial entries from A and B
    let mut stronghold = Stronghold::init_stronghold_system(client_path0.clone(), vec![])
        .await
        .unwrap();

    // reload A
    let all_paths = vec![
        client_path0.clone(),
        client_path1.clone(),
        client_path2.clone(),
        client_path3.clone(),
    ];

    let former = client_path0.clone();

    // keep the reference to the current client id
    // synchronize the other client_path with this snapshot
    for client_path in all_paths {
        stronghold
            .read_snapshot(
                client_path.clone(),
                Some(former.clone()),
                &key_a,
                None,
                Some(storage_path_a.into()),
            )
            .await;
    }

    let mut key_a_static = [0u8; 32];
    key_a_static.clone_from_slice(&key_a);

    let mut key_b_static = [0u8; 32];
    key_b_static.clone_from_slice(&key_b);

    let mut key_destination_static = [0u8; 32];
    key_destination_static.clone_from_slice(&key_destination);

    // partially synchronize with other snapshot
    stronghold
        .synchronize_local_partial(
            ClientId::load_from_path(&client_path0.clone(), &client_path0.clone()).unwrap(),
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_a.into()),
                key: key_a_static,
                generates_output: false,
            },
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_b.into()),
                key: key_b_static,
                generates_output: false,
            },
            SnapshotConfig {
                filename: None,
                path: Some(storage_path_destination.into()),
                key: key_destination_static,
                generates_output: false,
            },
            allowed,
        )
        .await;

    assert!(!stronghold.vault_exists(loc_b0).await);
    assert!(stronghold.vault_exists(loc_b1).await);
}

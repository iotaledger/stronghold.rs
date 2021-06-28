// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! snapshots synchronization tests

use crate::{naive_kdf, ActorSystem, Location, RecordHint, StatusMessage, Stronghold};
use engine::snapshot::Key;
use rand::Rng;
use std::{env::temp_dir, error::Error, io, path::PathBuf};
use tokio::runtime::Runtime;
use zeroize::Zeroize;

// macros
macro_rules! keygen {
    ($pass:expr) => {
        create_key($pass, None).expect("Could not create key");
    };
    ($pass:expr, $salt:expr) => {
        create_key($pass, Some($salt)).expect("Could not create key");
    };
}

macro_rules! delete_files {
    ($path:expr) => {
        delete_file($path).expect("Could not delete file");
    };
    ($($path:expr),+) => {
        $(
            delete_file($path).expect("Could not delete file");
        )+
    }
}

#[derive(Clone)]
struct TestConfig {
    entries: Vec<TestEntry>,
    record_hint: RecordHint,
    password: Vec<u8>,
    output: Option<PathBuf>,
}

#[derive(Clone)]
struct TestEntry {
    client_path: Vec<u8>,
    vault_path: Vec<u8>,
    record_path: Vec<u8>,
    payload: Vec<u8>,
}

impl From<TestEntry> for Location {
    fn from(p: TestEntry) -> Self {
        Location::Generic {
            record_path: p.record_path,
            vault_path: p.vault_path,
        }
    }
}

/// creates a snapshot inside temp dir, returns the path and filename as tuple
/// on successful creating a snapshot
async fn create_snapshot<K>(
    path: PathBuf,
    keydata: K,
    payload: Vec<u8>,
    system: ActorSystem,
    config: TestConfig,
) -> Result<PathBuf, Box<dyn Error>>
where
    K: Zeroize + AsRef<Vec<u8>>,
{
    let mut stronghold = Stronghold::init_stronghold_system(system, config.entries[0].client_path.clone(), vec![]);

    // write records to store
    stronghold
        .write_to_store(
            Location::Generic {
                vault_path: config.entries[0].vault_path.clone(),
                record_path: config.entries[0].record_path.clone(),
            },
            payload.clone(),
            None,
        )
        .await
        .map_err(|err| err)?;

    // write records to vault
    stronghold
        .write_to_vault(
            Location::Generic {
                vault_path: config.entries[0].vault_path.clone(),
                record_path: config.entries[0].record_path.clone(),
            },
            payload.clone(),
            config.record_hint,
            vec![],
        )
        .await
        .map_err(|err| err)?;

    // write snapshot
    stronghold
        .write_all_to_snapshot(keydata.as_ref(), None, Some(path.clone()))
        .await
        .map_err(|err| err)?;

    // verify vault entry
    verify_payload(
        &mut stronghold,
        payload.clone(),
        Location::Generic {
            vault_path: config.entries[0].vault_path.clone(),
            record_path: config.entries[0].record_path.clone(),
        },
    )
    .await
    .map(|_| path)
}

async fn verify_payload(
    stronghold: &mut Stronghold,
    payload: Vec<u8>,
    location: Location,
) -> Result<(), Box<dyn Error>> {
    let secret = stronghold.read_secret(location).await;

    if secret.0.unwrap().eq(&payload) {
        Ok(())
    } else {
        Err("Payload mismatch".into())
    }
}

/// Creates a temporary file
fn create_temp_file() -> Result<PathBuf, io::Error> {
    let rng = rand::thread_rng().gen::<usize>();
    let mut dir = temp_dir();
    let name = format!("snapshot_{}", rng);
    dir.push(name);

    Ok(dir)
}

/// Creates a key from [`K`]
fn create_key_from<K>(data: K) -> Key
where
    K: Zeroize + AsRef<Vec<u8>>,
{
    let mut key = [0u8; 32];
    key.copy_from_slice(data.as_ref());
    key
}

/// Delete file
#[inline(always)]
fn delete_file(path: PathBuf) -> Result<(), io::Error> {
    std::fs::remove_file(path)
}
// Create a key from a passphrase
fn create_key(passphrase: &[u8], salt: Option<[u8; 32]>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = salt.unwrap_or([1u8; 32]);
    naive_kdf(passphrase, &salt, &mut key)?;

    Ok(key.to_vec())
}

// Creates a testing target
fn create_test_table() -> Vec<(TestConfig, TestConfig, TestConfig)> {
    vec![(
        TestConfig {
            entries: vec![TestEntry {
                client_path: b"client_path_a".to_vec(),
                vault_path: b"vault_path_a".to_vec(),
                record_path: b"record_path_a".to_vec(),
                payload: b"AAA:payload".to_vec(),
            }],
            record_hint: RecordHint::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("Could not create `RecordHint`"),
            password: b"password2".to_vec(),
            output: None,
        },
        TestConfig {
            entries: vec![TestEntry {
                client_path: b"client_path_b".to_vec(),
                vault_path: b"vault_path_b".to_vec(),
                record_path: b"record_path_b".to_vec(),
                payload: b"BBB:payload".to_vec(),
            }],
            record_hint: RecordHint::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("Could not create `RecordHint`"),
            password: b"password2".to_vec(),
            output: None,
        },
        // todo: this is the expected value, and needs to test all available paths
        TestConfig {
            entries: vec![
                TestEntry {
                    client_path: b"client_path_b".to_vec(),
                    vault_path: b"vault_path_b".to_vec(),
                    record_path: b"record_path_b".to_vec(),
                    payload: b"BBB:payload".to_vec(),
                },
                TestEntry {
                    client_path: b"client_path_a".to_vec(),
                    vault_path: b"vault_path_a".to_vec(),
                    record_path: b"record_path_a".to_vec(),
                    payload: b"AAA:payload".to_vec(),
                },
            ],
            record_hint: RecordHint::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("Could not create `RecordHint`"),
            password: b"password2".to_vec(),
            output: Some(create_temp_file().expect("Could not create temp file")),
        },
    )]
}

#[test]
fn test_synchronize_local_snapshots() -> Result<(), Box<dyn Error>> {
    // load stronghold and check all entries
    let runtime = Runtime::new()?;

    create_test_table()
        .into_iter()
        .for_each(|(config_a, config_b, config_expected)| {
            runtime.block_on(async {
                // locals
                let keydata_a = keygen!(&config_a.password);
                let _key_a = create_key_from(keydata_a.clone());
                let keydata_b = keygen!(&config_b.password);
                let key_b = create_key_from(keydata_b.clone());

                // target config
                let p_target = create_temp_file().expect("Failed to create temp file");
                let keydata_target = keygen!(&config_expected.password);
                let k_target = create_key_from(keydata_target.clone());

                // locations
                let loc_a = config_a.clone().entries[0].clone();
                let loc_b = config_b.clone().entries[0].clone();

                // create snapshot a and b
                let a = create_snapshot(
                    create_temp_file().expect("Failed to create temporary file"),
                    keydata_a,
                    config_a.entries[0].payload.clone(),
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    config_a.clone(),
                )
                .await
                .expect("Could not create snapshot a");

                let b = create_snapshot(
                    create_temp_file().expect("Failed to create temporary file"),
                    keydata_b,
                    config_b.entries[0].payload.clone(),
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    config_b.clone(),
                )
                .await
                .expect("Could not create snapshot b");

                // for paths in
                // load synchronized snapshot
                let mut stronghold = Stronghold::init_stronghold_system(
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    config_a.clone().entries[0].client_path.clone(),
                    vec![],
                );

                // load snapshot a
                stronghold
                    .read_snapshot(
                        config_a.clone().entries[0].client_path.clone(),
                        Some(config_a.clone().entries[0].client_path.clone()),
                        &keygen!(&config_a.password),
                        None,
                        Some(a.clone()),
                    )
                    .await
                    .map_err(|err| err)
                    .expect("Could not load synchronized snapshot");

                // synchronize snapshot a with b
                assert!(
                    matches!(
                        stronghold
                            .synchronize_snapshot(
                                config_a.clone().entries[0].client_path.clone(),
                                key_b,
                                None,
                                Some(b.clone()),
                                p_target.clone(),
                                k_target,
                            )
                            .await,
                        StatusMessage::OK
                    ),
                    "Synchronizing two snapshots failed"
                );

                for paths in config_expected.entries {
                    let loc_a = loc_a.clone();
                    let loc_b = loc_b.clone();

                    let mut stronghold = Stronghold::init_stronghold_system(
                        ActorSystem::new().expect("Failed to initialize actor system"),
                        paths.clone().client_path,
                        vec![],
                    );

                    stronghold
                        .read_snapshot(
                            paths.clone().client_path,
                            Some(paths.clone().client_path),
                            &keydata_target, // fixme: not needed
                            None,
                            Some(p_target.clone()),
                        )
                        .await;

                    // --- testing ---
                    match paths.clone().client_path.as_slice() {
                        b"client_path_a" => {
                            assert_eq!(
                                stronghold.read_from_store(loc_a.clone().into()).await.0,
                                config_a.clone().entries[0].payload
                            );
                            if let Some(data) = stronghold.read_secret(loc_a.into()).await.0 {
                                assert_eq!(data, config_a.clone().entries[0].payload);
                            }
                        }
                        b"client_path_b" => {
                            assert_eq!(
                                stronghold.read_from_store(loc_b.clone().into()).await.0,
                                config_b.clone().entries[0].payload
                            );
                            if let Some(data) = stronghold.read_secret(loc_b.into()).await.0 {
                                assert_eq!(data, config_b.clone().entries[0].payload);
                            }
                        }
                        _ => {}
                    }
                }
                // --- finalize ---
                delete_files!(a, b);
            });
        });

    Ok(())
}

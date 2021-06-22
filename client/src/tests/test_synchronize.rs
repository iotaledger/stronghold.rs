// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! snapshots synchronization tests

use crate::{naive_kdf, ActorSystem, Location, RecordHint, Snapshot, Stronghold};
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

/// creates a snapshot inside temp dir, returns the path and filename as tuple
/// on successful creating a snapshot
async fn create_snapshot<K>(
    path: PathBuf,
    keydata: K,
    payload: Vec<u8>,
    system: ActorSystem,
    config: TestConfig,
) -> Result<(Snapshot, PathBuf), Box<dyn Error>>
where
    K: Zeroize + AsRef<Vec<u8>>,
{
    let mut stronghold = Stronghold::init_stronghold_system(system, config.paths.client_path.clone(), vec![]);

    // write to store
    stronghold
        .write_to_store(
            Location::Generic {
                vault_path: config.paths.vault_path.clone(),
                record_path: config.paths.record_path.clone(),
            },
            payload.clone(),
            None,
        )
        .await
        .map_err(|err| err)?;

    // write to vault
    stronghold
        .write_to_vault(
            Location::Generic {
                vault_path: config.paths.vault_path.clone(),
                record_path: config.paths.record_path.clone(),
            },
            payload,
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

    Ok((
        Snapshot::read_snapshot_with_full_path(path.clone(), &create_key_from(keydata))?,
        path,
    ))
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
fn delete_file(path: PathBuf) -> Result<(), io::Error> {
    std::fs::remove_file(path)
}

fn create_key(passphrase: &[u8], salt: Option<[u8; 32]>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = salt.unwrap_or([1u8; 32]);
    naive_kdf(passphrase, &salt, &mut key)?;

    Ok(key.to_vec())
}

fn create_payload() -> Vec<u8> {
    let mut payload = [0u8; 256];
    rand::thread_rng().fill(&mut payload);
    payload.to_vec()
}

#[derive(Clone)]
struct TestConfig {
    paths: TestPath,
    record_hint: RecordHint,
    password: Vec<u8>,
    output: Option<PathBuf>,
}

#[derive(Clone)]
struct TestPath {
    client_path: Vec<u8>,
    vault_path: Vec<u8>,
    record_path: Vec<u8>,
}

// Creates a testing target
fn create_test_table() -> Vec<(TestConfig, TestConfig, TestConfig)> {
    vec![(
        TestConfig {
            paths: TestPath {
                client_path: b"client_path".to_vec(),
                vault_path: b"vault_path".to_vec(),
                record_path: b"record_path".to_vec(),
            },
            record_hint: RecordHint::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("Could not create `RecordHint`"),
            password: b"password2".to_vec(),
            output: None,
        },
        TestConfig {
            paths: TestPath {
                client_path: b"client_path".to_vec(),
                vault_path: b"vault_path".to_vec(),
                record_path: b"record_path".to_vec(),
            },
            record_hint: RecordHint::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("Could not create `RecordHint`"),
            password: b"password2".to_vec(),
            output: None,
        },
        TestConfig {
            paths: TestPath {
                client_path: b"client_path".to_vec(),
                vault_path: b"vault_path".to_vec(),
                record_path: b"record_path".to_vec(),
            },
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
                // create snapshot a and b
                let a = create_snapshot(
                    create_temp_file().expect("Failed to create temporary file"),
                    keygen!(&config_a.password),
                    create_payload(),
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    config_a.clone(),
                )
                .await
                .expect("Could not create snapshot a");

                let b = create_snapshot(
                    create_temp_file().expect("Failed to create temporary file"),
                    keygen!(&config_b.clone().password),
                    create_payload(),
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    config_b.clone(),
                )
                .await
                .expect("Could not create snapshot b");

                // synchronized snapshot
                let sync =
                    a.0.synchronize(b.1.clone(), create_key_from(keygen!(&config_b.password)))
                        .expect("Failed to synchronize snapshots");

                // write snapshot
                let output = config_expected.output.unwrap();
                sync.write_to_snapshot(
                    None,
                    Some(output.clone().as_path()),
                    create_key_from(keygen!(&config_expected.password)),
                )
                .expect("Could not write synchronized snapshot");

                // --- testing ---
                // load synchronized snapshot
                let mut stronghold = Stronghold::init_stronghold_system(
                    ActorSystem::new().expect("Failed to initialize actor system"),
                    vec![],
                    vec![],
                );
                stronghold
                    .read_snapshot(
                        config_expected.paths.client_path,
                        None,
                        &keygen!(&config_expected.password),
                        None,
                        Some(output.clone()),
                    )
                    .await
                    .map_err(|err| err)
                    .expect("Could not load synchronized snapshot");

                // --- finalize ---
                delete_files!(a.1, b.1, output);
            });
        });

    Ok(())
}

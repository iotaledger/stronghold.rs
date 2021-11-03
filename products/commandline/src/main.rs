// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use clap::{load_yaml, App, ArgMatches};
use core::panic;
use futures::executor::block_on;
use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, Stronghold};
use std::path::{Path, PathBuf};

// create a line error with the file and the line number
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

// Writes data to the unencrypted store. Requires a password, the plaintext and the record path.  Record path must be a
// number.
fn write_to_store_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("write") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(rid) = matches.value_of("rpath") {
                    let mut key = [0u8; 32];
                    let salt = [0u8; 32];
                    naive_kdf(pass.as_bytes(), &salt, &mut key);

                    let home_dir = home_dir().expect(line_error!());
                    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                    if snapshot.exists() {
                        let result = block_on(stronghold.read_snapshot(
                            client_path,
                            None,
                            &key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ))
                        .unwrap();
                        if let Err(e) = result {
                            println!("[Error] Reading snapshot failed: {}", e);
                            return;
                        }
                    }

                    let old_value =
                        block_on(stronghold.write_to_store(rid.into(), plain.as_bytes().to_vec(), None)).unwrap();
                    match old_value {
                        Some(v) => println!("Wrote to store. Overwrote old data: {:?}", v),
                        None => println!("Wrote to store."),
                    }

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Writing snapshot failed: {}", e);
                    }
                };
            };
        };
    }
}

/// Writes data to the encrypted vault.  Requires a password, the plaintext and the record path.  Record path must be a
/// number.
fn encrypt_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(rid) = matches.value_of("rpath") {
                    let mut key = [0u8; 32];
                    let salt = [0u8; 32];
                    naive_kdf(pass.as_bytes(), &salt, &mut key);

                    let home_dir = home_dir().expect(line_error!());
                    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                    if snapshot.exists() {
                        let result = block_on(stronghold.read_snapshot(
                            client_path,
                            None,
                            &key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ))
                        .unwrap();
                        if let Err(e) = result {
                            println!("[Error] Reading snapshot failed: {}", e);
                            return;
                        }
                    }

                    let result = block_on(stronghold.write_to_vault(
                        Location::generic(rid, rid),
                        plain.as_bytes().to_vec(),
                        RecordHint::new("some hint").expect(line_error!()),
                        vec![],
                    ))
                    .unwrap();
                    match result {
                        Ok(()) => println!("Wrote to vault."),
                        Err(e) => {
                            println!("[Error] Writing to vault failed: {}", e);
                            return;
                        }
                    }

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Writing snapshot failed: {}", e);
                    }
                };
            };
        };
    }
}

// Writes the state of the stronghold to a snapshot. Requires a password and an optional snapshot path.
fn snapshot_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("snapshot") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(ref path) = matches.value_of("path") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let path = Path::new(path);

                let input = path.to_path_buf();

                let output = path.parent().expect(line_error!());
                let mut out = PathBuf::new();
                out.push(output);
                out.push(Path::new("recompute.stronghold"));

                if input.exists() {
                    let result =
                        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), None, Some(input)))
                            .unwrap();
                    match result {
                        Ok(()) => println!("Read snapshot"),
                        Err(e) => {
                            println!("[Error] Reading snapshot failed: {}", e);
                            return;
                        }
                    }

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    match result {
                        Ok(()) => println!("Wrote to snapshot."),
                        Err(e) => {
                            println!("[Error] Writing snapshot failed: {}", e);
                        }
                    }
                } else {
                    println!("[Error] The path you entered does not contain a valid snapshot");
                }
            }
        }
    }
}

// Lists the records in the stronghold. Requires a password to unlock the snapshot.
fn list_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("list") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(path) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    let result = block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Reading snapshot failed: {}", e);
                        return;
                    }

                    let list =
                        block_on(stronghold.list_hints_and_ids(Location::generic(path, path).vault_path().to_vec()))
                            .unwrap();
                    println!("Hints and Ids:");
                    for (id, hint) in list {
                        println!("{}: {:?}", id, hint);
                    }
                } else {
                    println!("[Error] Could not find a snapshot at the home path. Try writing first.");
                }
            }
        }
    }
}

// Reads a record from the unencrypted store.  Requires a snapshot password.
fn read_from_store_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(rpath) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    let result = block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Reading snapshot failed: {}", e);
                        return;
                    }

                    let data = block_on(stronghold.read_from_store(rpath.into())).unwrap();
                    match data {
                        Some(data) => println!("Data: {:?}", std::str::from_utf8(&data).unwrap()),
                        None => println!("No Data in the store for this key."),
                    }
                } else {
                    println!("[Error] Could not find a snapshot at the home path. Try writing first.");
                }
            }
        }
    }
}

// Revoke a record.  Data isn't actually deleted until it is garbage collected.  Accepts a password and the record id
// that you want to revoke.
fn revoke_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("revoke") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(id) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    let result = block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Reading snapshot failed: {}", e);
                        return;
                    }

                    let result = block_on(stronghold.delete_data(Location::generic(id, id), false)).unwrap();
                    match result {
                        Ok(()) => println!("Deleted data."),
                        Err(e) => {
                            println!("[Error] Deleting data failed: {}", e);
                            return;
                        }
                    }

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Writing snapshot failed: {}", e);
                    }
                } else {
                    println!("[Error] Could not find a snapshot at the home path. Try writing first.");
                }
            }
        }
    }
}

// garbage collect the chain.  Remove any revoked data from the chain.  Requires the password.
fn garbage_collect_vault_command(
    matches: &ArgMatches,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    if let Some(matches) = matches.subcommand_matches("garbage_collect") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(id) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    let result = block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Reading snapshot failed: {}", e);
                        return;
                    }

                    let result =
                        block_on(stronghold.garbage_collect(Location::generic(id, id).vault_path().to_vec())).unwrap();
                    match result {
                        true => println!("Garbage collected."),
                        false => println!("[Error] Vault does not exist."),
                    }

                    let list = block_on(stronghold.list_hints_and_ids(Location::generic(id, id).vault_path().to_vec()))
                        .unwrap();
                    println!("Hints and Ids:");
                    for (id, hint) in list {
                        println!("{}: {:?}", id, hint);
                    }

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Writing snapshot failed: {}", e);
                    }
                } else {
                    println!("[Error] Could not find a snapshot at the home path. Try writing first.");
                }
            }
        }
    }
}

// Purge a record from the chain.  Calls revoke and garabge collect in one command.  Requires a password and the record
// id.
fn purge_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("purge") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(id) = matches.value_of("id") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key);

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    let result = block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Reading snapshot failed: {}", e);
                        return;
                    }

                    let result = block_on(stronghold.delete_data(Location::generic(id, id), true)).unwrap();

                    println!("Delete Data: {:?}", result);

                    let result = block_on(stronghold.write_all_to_snapshot(
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ))
                    .unwrap();
                    if let Err(e) = result {
                        println!("[Error] Writing snapshot failed: {}", e);
                    }
                } else {
                    println!("[Error] Could not find a snapshot at the home path. Try writing first.");
                }
            }
        }
    }
}

#[actix::main]
async fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    let client_path = b"actor_path".to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![])
        .await
        .unwrap_or_else(|e| panic!("Failed to initialize stronghold system: {}", e));

    write_to_store_command(&matches, &mut stronghold, client_path.clone());
    encrypt_command(&matches, &mut stronghold, client_path.clone());
    snapshot_command(&matches, &mut stronghold, client_path.clone());
    read_from_store_command(&matches, &mut stronghold, client_path.clone());
    list_command(&matches, &mut stronghold, client_path.clone());
    revoke_command(&matches, &mut stronghold, client_path.clone());
    garbage_collect_vault_command(&matches, &mut stronghold, client_path.clone());
    purge_command(&matches, &mut stronghold, client_path);
}

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]

use iota_stronghold::{
    home_dir, naive_kdf, Location, RecordHint, StatusMessage, Stronghold, StrongholdFlags, VaultFlags,
};

use futures::executor::block_on;

use riker::actors::*;

use clap::{load_yaml, App, ArgMatches};

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

// handle the encryption command.
fn encrypt_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(rid) = matches.value_of("rpath") {
                    let mut key = [0u8; 32];
                    let salt = [0u8; 32];
                    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                    let home_dir = home_dir().expect(line_error!());
                    let mut snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                    if snapshot.exists() {
                        block_on(stronghold.read_snapshot(
                            client_path.clone(),
                            None,
                            key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ));
                    }

                    block_on(stronghold.write_data(
                        Location::counter::<_, usize>("test", Some(rid.parse::<usize>().unwrap())),
                        plain.as_bytes().to_vec(),
                        RecordHint::new(b"some hint").expect(line_error!()),
                        vec![],
                    ));

                    block_on(stronghold.write_all_to_snapshot(key.to_vec(), Some("commandline".to_string()), None));
                };
            };
        };
    }
}

// handle the snapshot command.
fn snapshot_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("snapshot") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref path) = matches.value_of("path") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let path = Path::new(path);

                let input = path.to_path_buf();

                let output = path.parent().expect(line_error!());
                let mut out = PathBuf::new();
                out.push(output);
                out.push(Path::new("recompute.stronghold"));

                if input.exists() {
                    let status =
                        block_on(stronghold.read_snapshot(client_path.clone(), None, key.to_vec(), None, Some(input)));

                    if let StatusMessage::Error(error) = status {
                        println!("{:?}", error);
                        return;
                    } else {
                        block_on(stronghold.write_all_to_snapshot(key.to_vec(), Some("commandline".to_string()), None));
                    }
                } else {
                    println!("The path you entered does not contain a valid snapshot");
                }
            }
        }
    }
}

// handle the list command.
fn list_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("list") {
        if let Some(ref pass) = matches.value_of("password") {
            let mut key = [0u8; 32];
            let salt = [0u8; 32];
            naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

            let home_dir = home_dir().expect(line_error!());
            let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

            if snapshot.exists() {
                block_on(stronghold.read_snapshot(
                    client_path,
                    None,
                    key.to_vec(),
                    Some("commandline".to_string()),
                    None,
                ));

                let (list, status) = block_on(stronghold.list_hints_and_ids(b"test".to_vec()));

                println!("{:?}", status);
                println!("{:?}", list);
            } else {
                println!("Could not find a snapshot at the home path.  Try writing first. ");

                return;
            }
        }
    }
}

// handle the read command.
fn read_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let (data, status) = block_on(stronghold.read_data(Location::counter::<_, usize>(
                        "test",
                        Some(id.parse::<usize>().unwrap()),
                    )));

                    println!("{:?}", status);
                    println!("Data: {:?}", std::str::from_utf8(&data.unwrap()).unwrap());
                } else {
                    println!("Could not find a snapshot at the home path.  Try writing first. ");

                    return;
                }
            }
        }
    }
}

// create a record with a revoke transaction.  Data isn't actually deleted until it is garbage collected.
fn revoke_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("revoke") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let status = block_on(stronghold.delete_data(
                        Location::counter::<_, usize>("test", Some(id.parse::<usize>().unwrap())),
                        false,
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(key.to_vec(), Some("commandline".to_string()), None));
                } else {
                    println!("Could not find a snapshot at the home path.  Try writing first. ");

                    return;
                }
            }
        }
    }
}

// garbage collect the chain.  Remove any revoked data from the chain.
fn garbage_collect_vault_command(
    matches: &ArgMatches,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    if let Some(matches) = matches.subcommand_matches("garbage_collect") {
        if let Some(ref pass) = matches.value_of("password") {
            let mut key = [0u8; 32];
            let salt = [0u8; 32];
            naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

            let home_dir = home_dir().expect(line_error!());
            let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

            if snapshot.exists() {
                block_on(stronghold.read_snapshot(
                    client_path,
                    None,
                    key.to_vec(),
                    Some("commandline".to_string()),
                    None,
                ));

                let status = block_on(stronghold.garbage_collect(b"test".to_vec()));

                println!("{:?}", status);

                block_on(stronghold.write_all_to_snapshot(key.to_vec(), Some("commandline".to_string()), None));
            } else {
                println!("Could not find a snapshot at the home path.  Try writing first. ");

                return;
            }
        }
    }
}

// Purge a record from the chain: revoke and then garbage collect.
fn purge_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("purge") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let status = block_on(stronghold.delete_data(
                        Location::counter::<_, usize>(b"test".to_vec(), Some(id.parse::<usize>().unwrap())),
                        true,
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(key.to_vec(), Some("commandline".to_string()), None));
                } else {
                    println!("Could not find a snapshot at the home path.  Try writing first. ");

                    return;
                }
            }
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    let system = ActorSystem::new().expect(line_error!());
    let client_path = b"actor_path".to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(system, client_path.clone(), vec![]);

    encrypt_command(&matches, &mut stronghold, client_path.clone());
    snapshot_command(&matches, &mut stronghold, client_path.clone());
    read_command(&matches, &mut stronghold, client_path.clone());
    list_command(&matches, &mut stronghold, client_path.clone());
    revoke_command(&matches, &mut stronghold, client_path.clone());
    garbage_collect_vault_command(&matches, &mut stronghold, client_path.clone());
    purge_command(&matches, &mut stronghold, client_path);
}

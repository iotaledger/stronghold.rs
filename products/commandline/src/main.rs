// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, StatusMessage, Stronghold};

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

// Writes data to the unencrypted store. Requires a password, the plaintext and the record path.  Record path must be a number.
fn write_to_store_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("write") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(rid) = matches.value_of("rpath") {
                    let mut key = [0u8; 32];
                    let salt = [0u8; 32];
                    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                    let home_dir = home_dir().expect(line_error!());
                    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                    if snapshot.exists() {
                        block_on(stronghold.read_snapshot(
                            client_path,
                            None,
                            &key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ));
                    }

                    let status = block_on(stronghold.write_to_store(
                        Location::counter::<_, usize>("test", Some(rid.parse::<usize>().unwrap())),
                        plain.as_bytes().to_vec(),
                        None,
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
                };
            };
        };
    }
}

/// Writes data to the encrypted vault.  Requires a password, the plaintext and the record path.  Record path must be a number.
fn encrypt_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(rid) = matches.value_of("rpath") {
                    let mut key = [0u8; 32];
                    let salt = [0u8; 32];
                    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                    let home_dir = home_dir().expect(line_error!());
                    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                    if snapshot.exists() {
                        block_on(stronghold.read_snapshot(
                            client_path,
                            None,
                            &key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ));
                    }

                    let status = block_on(stronghold.write_to_vault(
                        Location::counter::<_, usize>("test", Some(rid.parse::<usize>().unwrap())),
                        plain.as_bytes().to_vec(),
                        RecordHint::new("some hint").expect(line_error!()),
                        vec![],
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
                };
            };
        };
    }
}

// Writes the state of the stronghold to a snapshot. Requires a password and an optional snapshot path.
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
                        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), None, Some(input)));

                    if let StatusMessage::Error(error) = status {
                        println!("{:?}", error);
                        return;
                    } else {
                        block_on(stronghold.write_all_to_snapshot(
                            &key.to_vec(),
                            Some("commandline".to_string()),
                            None,
                        ));
                    }
                } else {
                    println!("The path you entered does not contain a valid snapshot");
                }
            }
        }
    }
}

// Lists the records in the stronghold. Requires a password to unlock the snapshot.
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
                    &key.to_vec(),
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

// Reads a record from the unencrypted store.  Requires a snapshot password.
fn read_from_store_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref rpath) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let (data, status) = block_on(stronghold.read_from_store(Location::counter::<_, usize>(
                        "test",
                        Some(rpath.parse::<usize>().unwrap()),
                    )));

                    println!("{:?}", status);
                    println!("Data: {:?}", std::str::from_utf8(&data).unwrap());
                } else {
                    println!("Could not find a snapshot at the home path.  Try writing first. ");

                    return;
                }
            }
        }
    }
}

// Revoke a record.  Data isn't actually deleted until it is garbage collected.  Accepts a password and the record id that you want to revoke.
fn revoke_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    if let Some(matches) = matches.subcommand_matches("revoke") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("rpath") {
                let mut key = [0u8; 32];
                let salt = [0u8; 32];
                naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

                let home_dir = home_dir().expect(line_error!());
                let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

                if snapshot.exists() {
                    block_on(stronghold.read_snapshot(
                        client_path,
                        None,
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let status = block_on(stronghold.delete_data(
                        Location::counter::<_, usize>("test", Some(id.parse::<usize>().unwrap())),
                        false,
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
                } else {
                    println!("Could not find a snapshot at the home path.  Try writing first. ");

                    return;
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
                    &key.to_vec(),
                    Some("commandline".to_string()),
                    None,
                ));

                let status = block_on(stronghold.garbage_collect(b"test".to_vec()));

                let (list, _) = block_on(stronghold.list_hints_and_ids(b"test".to_vec()));

                println!("{:?}", status);
                println!("{:?}", list);

                block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
            } else {
                println!("Could not find a snapshot at the home path.  Try writing first. ");

                return;
            }
        }
    }
}

// Purge a record from the chain.  Calls revoke and garabge collect in one command.  Requires a password and the record id.
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
                        &key.to_vec(),
                        Some("commandline".to_string()),
                        None,
                    ));

                    let status = block_on(stronghold.delete_data(
                        Location::counter::<_, usize>(b"test".to_vec(), Some(id.parse::<usize>().unwrap())),
                        true,
                    ));

                    println!("{:?}", status);

                    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
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

    write_to_store_command(&matches, &mut stronghold, client_path.clone());
    encrypt_command(&matches, &mut stronghold, client_path.clone());
    snapshot_command(&matches, &mut stronghold, client_path.clone());
    read_from_store_command(&matches, &mut stronghold, client_path.clone());
    list_command(&matches, &mut stronghold, client_path.clone());
    revoke_command(&matches, &mut stronghold, client_path.clone());
    garbage_collect_vault_command(&matches, &mut stronghold, client_path.clone());
    purge_command(&matches, &mut stronghold, client_path);
}

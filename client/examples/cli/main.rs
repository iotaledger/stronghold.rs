// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod arguments;

use arguments::*;
use clap::{ArgMatches, Clap};
use futures::executor::block_on;
use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, StatusMessage, Stronghold};
use riker::actors::*;

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
fn write_to_store_command(
    pass: &str,
    plain: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));
    }

    let status = block_on(stronghold.write_to_store(Location::generic(rid, rid), plain.as_bytes().to_vec(), None));

    println!("{:?}", status);

    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
}

/// Writes data to the encrypted vault.  Requires a password, the plaintext and the record path.  Record path must be a
/// number.
fn encrypt_command(
    plain: &str,
    pass: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));
    }

    let status = block_on(stronghold.write_to_vault(
        Location::generic(rid, rid),
        plain.as_bytes().to_vec(),
        RecordHint::new("some hint").expect(line_error!()),
        vec![],
    ));

    println!("{:?}", status);

    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
}

/// Loads a snapshot from another stronghold instance, and loads it into the current one
fn snapshot_command(pass: &str, path: &str, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
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
        let status = block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), None, Some(input)));

        if let StatusMessage::Error(error) = status {
            println!("{:?}", error);
            return;
        } else {
            block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
        }
    } else {
        println!("The path you entered does not contain a valid snapshot");
    }
}

// Lists the records in the stronghold. Requires a password to unlock the snapshot.
fn list_command(pass: &str, path: &str, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        println!("reading");

        let (list, status) =
            block_on(stronghold.list_hints_and_ids(Location::generic(path, path).vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);
    } else {
        println!("Could not find a snapshot at the home path.  Try writing first. ");

        return;
    }
}

// Reads a record from the unencrypted store.  Requires a snapshot password.
fn read_from_store_command(
    pass: &str,
    rpath: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let (data, status) = block_on(stronghold.read_from_store(Location::generic(rpath, rpath)));

        println!("{:?}", status);
        println!("Data: {:?}", std::str::from_utf8(&data).unwrap());
    } else {
        println!("Could not find a snapshot at the home path.  Try writing first. ");

        return;
    }
}

// Revoke a record.  Data isn't actually deleted until it is garbage collected.  Accepts a password and the record id
// that you want to revoke.
fn revoke_command(pass: &str, id: &str, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let status = block_on(stronghold.delete_data(Location::generic(id, id), false));

        println!("{:?}", status);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        println!("Could not find a snapshot at the home path.  Try writing first. ");

        return;
    }
}

// garbage collect the chain.  Remove any revoked data from the chain.  Requires the password.
fn garbage_collect_vault_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let location = Location::generic(id, id);

        let status = block_on(stronghold.garbage_collect(location.vault_path().to_vec()));

        let (list, _) = block_on(stronghold.list_hints_and_ids(location.vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        println!("Could not find a snapshot at the home path.  Try writing first. ");

        return;
    }
}

// Purge a record from the chain.  Calls revoke and garbage collect in one command.  Requires a password and the record
// id.
fn purge_command(pass: &str, id: &str, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let home_dir = home_dir().expect(line_error!());
    let snapshot = home_dir.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let location = Location::generic(id, id);

        let status = block_on(stronghold.delete_data(location.clone(), true));

        let (list, _) = block_on(stronghold.list_hints_and_ids(location.vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        println!("Could not find a snapshot at the home path.  Try writing first. ");

        return;
    }
}

fn take_ownership_command(password: &str, stronghold: &mut Stronghold, client_path: Vec<u8>) {
    todo!()
}

/// Relays a request to a remote stronghold instance.
///
#[cfg(feature = "communication")]
fn relay_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    // needs:
    // peer_id: usize,
    // key: Vec<u8>,
    todo!()
}

/// Returns a list of all available peers
#[cfg(feature = "communication")]
fn peers_command(matches: &ArgMatches, stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) {
    // stronghold.

    todo!()
}

///

fn main() {
    // a complete sequence of writing an encrypted secret into the vault is:
    // - write the secret at path 0
    // - encrypt the secret at storage position 0 and write snapshot
    // - list the existing records
    // - read entry at path 0

    let system = ActorSystem::new().expect(line_error!());
    let client_path = b"actor_path".to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(system, client_path.clone(), vec![]);

    match Commands::parse().cmds {
        SubCommands::Encrypt {
            plain,
            pass,
            record_path,
        } => {
            encrypt_command(
                plain.as_str(),
                pass.as_str(),
                record_path.as_str(),
                &mut stronghold,
                client_path,
            );
        }
        SubCommands::GarbageCollect { pass, id } => {
            garbage_collect_vault_command(pass.as_str(), id.as_str(), &mut stronghold, client_path);
        }
        SubCommands::List { pass, record_path } => {
            list_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path);
        }
        SubCommands::Purge { password, id } => {
            purge_command(password.as_str(), id.as_str(), &mut stronghold, client_path)
        }
        SubCommands::Read { pass, record_path } => {
            read_from_store_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path);
        }
        SubCommands::Revoke { id, password } => {
            revoke_command(password.as_str(), id.as_str(), &mut stronghold, client_path)
        }
        SubCommands::Snapshot { path, pass } => {
            snapshot_command(pass.as_str(), path.as_str(), &mut stronghold, client_path)
        }
        SubCommands::TakeOwnership { password } => {
            take_ownership_command(password.as_str(), &mut stronghold, client_path);
        }
        SubCommands::Write {
            pass,
            record_path,
            plain,
        } => write_to_store_command(
            pass.as_str(),
            plain.as_str(),
            record_path.as_str(),
            &mut stronghold,
            client_path,
        ),

        #[cfg(feature = "communication")]
        SubCommands::Relay { id, path } => {
            todo!()
        }
        #[cfg(feature = "communication")]
        SubCommands::Peers => {
            todo!()
        }
    }

    // let matches = App::from(yaml).get_matches();

    // write_to_store_command(&matches, &mut stronghold, client_path.clone());
    // encrypt_command(&matches, &mut stronghold, client_path.clone());
    // snapshot_command(&matches, &mut stronghold, client_path.clone());
    // read_from_store_command(&matches, &mut stronghold, client_path.clone());
    // list_command(&matches, &mut stronghold, client_path.clone());
    // revoke_command(&matches, &mut stronghold, client_path.clone());
    // garbage_collect_vault_command(&matches, &mut stronghold, client_path.clone());
    // purge_command(&matches, &mut stronghold, client_path.clone());

    // // added commands
    // relay_command(&matches, &mut stronghold, client_path.clone());
    // peers_command(&matches, &mut stronghold, client_path);
}

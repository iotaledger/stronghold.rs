// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod arguments;

use arguments::*;
use clap::{ArgMatches, Clap};
use futures::executor::block_on;
use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, ResultMessage, StatusMessage, Stronghold};
use riker::actors::*;
use std::error::Error;

use std::path::{Path, PathBuf};

/// create a line error with the file and the line number
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

/// Writes data to the unencrypted store. Requires a password, the plaintext and the record path.  Record path must be a
/// number.
fn write_to_store_command(
    pass: &str,
    plain: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));
    }

    let status = block_on(stronghold.write_to_store(Location::generic(rid, rid), plain.as_bytes().to_vec(), None));

    println!("{:?}", status);

    block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    Ok(())
}

/// Writes data to the encrypted vault.  Requires a password, the plaintext and the record path.  Record path must be a
/// number.
fn encrypt_command(
    plain: &str,
    pass: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

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

    Ok(())
}

//// Loads a snapshot from another stronghold instance, and loads it into the current one
fn snapshot_command(
    pass: &str,
    path: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
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
            return Err(Box::from(format!("{:?}", error)));
        } else {
            block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
        }
    } else {
        return Err(Box::from("The path you entered does not contain a valid snapshot"));
    }

    Ok(())
}

/// Lists the records in the stronghold. Requires a password to unlock the snapshot.
fn list_command(
    pass: &str,
    path: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        println!("reading");

        let (list, status) =
            block_on(stronghold.list_hints_and_ids(Location::generic(path, path).vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// Reads a record from the unencrypted store.  Requires a snapshot password.
fn read_from_store_command(
    pass: &str,
    rpath: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let (data, status) = block_on(stronghold.read_from_store(Location::generic(rpath, rpath)));

        println!("{:?}", status);
        println!("Data: {:?}", std::str::from_utf8(&data).unwrap());
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// Deletes from insecure store
fn delete_from_store_command(
    pass: &str,
    rpath: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let status_delete = block_on(stronghold.delete_from_store(Location::generic(rpath, rpath)));
        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
        println!("Delete: {:?}", status_delete);
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path. Try writing first.",
        ));
    }

    Ok(())
}

/// Revoke a record.  Data isn't actually deleted until it is garbage collected.  Accepts a password and the record id
/// that you want to revoke.
fn revoke_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));
        let status = block_on(stronghold.delete_data(Location::generic(id, id), false));

        println!("{:?}", status);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// garbage collect the chain.  Remove any revoked data from the chain.  Requires the password.
fn garbage_collect_vault_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));

        let location = Location::generic(id, id);
        let status = block_on(stronghold.garbage_collect(location.vault_path().to_vec()));
        let (list, _) = block_on(stronghold.list_hints_and_ids(location.vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first.",
        ));
    }

    Ok(())
}

/// Purge a record from the chain.  Calls revoke and garbage collect in one command.  Requires a password and the record
/// id.
fn purge_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key).expect(line_error!());

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        block_on(stronghold.read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None));
        let location = Location::generic(id, id);
        let status = block_on(stronghold.delete_data(location.clone(), true));
        let (list, _) = block_on(stronghold.list_hints_and_ids(location.vault_path().to_vec()));

        println!("{:?}", status);
        println!("{:?}", list);

        block_on(stronghold.write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None));
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first.",
        ));
    }
    Ok(())
}

fn take_ownership_command(
    _password: &str,
    _stronghold: &mut Stronghold,
    _client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    todo!()
}

/// Relays a request to a remote stronghold instance.
#[cfg(feature = "communication")]
fn relay_command(
    _matches: &ArgMatches,
    _stronghold: &mut iota_stronghold::Stronghold,
    _client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    todo!()
}

/// Returns a list of all available peers
#[cfg(feature = "communication")]
fn list_peers_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    match block_on(stronghold.get_swarm_info()) {
        ResultMessage::Ok((_, _, peers)) => {
            let info = format!(
                r#"
            Peers
            ===
            {:?}
            "#,
                peers
            );
            println!("{}", info)
        }
        ResultMessage::Error(e) => return Err(Box::from(format!("{}", e))),
    }

    Ok(())
}

/// Displays the swarm info of this stronghold instance
#[cfg(feature = "communication")]
fn show_swarm_info_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    match block_on(stronghold.get_swarm_info()) {
        ResultMessage::Ok((peer_id, addresses, peers)) => {
            let info = format!(
                r#"
                Swarm Info:
                ===
                Peer Id : {},
                Addresses: {:?},
                Peers: {:?}
            "#,
                peer_id, addresses, peers
            );

            println!("{}", info)
        }
        ResultMessage::Error(e) => return Err(Box::from(format!("{}", e))),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = ExampleApp::parse();
    let system = ActorSystem::new().expect(line_error!());
    let client_path = app.actor_path.as_bytes().to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(system, client_path.clone(), vec![]);

    match app.cmds {
        Commands::Encrypt {
            plain,
            pass,
            record_path,
        } => encrypt_command(
            plain.as_str(),
            pass.as_str(),
            record_path.as_str(),
            &mut stronghold,
            client_path,
        ),
        Commands::GarbageCollect { pass, id } => {
            garbage_collect_vault_command(pass.as_str(), id.as_str(), &mut stronghold, client_path)
        }
        Commands::List { pass, record_path } => {
            list_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path)
        }
        Commands::Purge { password, id } => purge_command(password.as_str(), id.as_str(), &mut stronghold, client_path),
        Commands::Read { pass, record_path } => {
            read_from_store_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path)
        }
        Commands::Revoke { id, password } => {
            revoke_command(password.as_str(), id.as_str(), &mut stronghold, client_path)
        }
        Commands::Snapshot { path, pass } => {
            snapshot_command(pass.as_str(), path.as_str(), &mut stronghold, client_path)
        }
        Commands::TakeOwnership { password } => take_ownership_command(password.as_str(), &mut stronghold, client_path),
        Commands::Write {
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
        Commands::Delete { record_path, pass } => {
            delete_from_store_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path)
        }

        #[cfg(feature = "communication")]
        Commands::Relay { id, path } => {
            todo!()
        }
        #[cfg(feature = "communication")]
        Commands::Peers {} => list_peers_command(&mut stronghold),

        #[cfg(feature = "communication")]
        Commands::SwarmInfo {} => show_swarm_info_command(&mut stronghold),
    }?;

    Ok(())
}

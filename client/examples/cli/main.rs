// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod arguments;

use arguments::*;
use clap::Clap;
use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, Stronghold};
use std::{
    error::Error,
    path::{Path, PathBuf},
};

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
async fn write_to_store_command(
    pass: &str,
    plain: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    }

    stronghold
        .write_to_store(rid.into(), plain.as_bytes().to_vec(), None)
        .await
        .unwrap();

    stronghold
        .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
        .await
        .unwrap();
    Ok(())
}

/// Writes data to the encrypted vault.  Requires a password, the plaintext and the record path.  Record path must be a
/// number.
async fn encrypt_command(
    plain: &str,
    pass: &str,
    rid: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    }

    stronghold
        .write_to_vault(
            Location::generic(rid, rid),
            plain.as_bytes().to_vec(),
            RecordHint::new("some hint").expect(line_error!()),
            vec![],
        )
        .await
        .unwrap();

    stronghold
        .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
        .await
        .unwrap();

    Ok(())
}

//// Loads a snapshot from another stronghold instance, and loads it into the current one
async fn snapshot_command(
    pass: &str,
    path: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
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
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), None, Some(input))
            .await
            .unwrap();
        stronghold
            .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    } else {
        return Err(Box::from("The path you entered does not contain a valid snapshot"));
    }

    Ok(())
}

/// Lists the records in the stronghold. Requires a password to unlock the snapshot.
async fn list_command(
    pass: &str,
    path: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();

        let list = stronghold
            .list_hints_and_ids(Location::generic(path, path).vault_path().to_vec())
            .await
            .unwrap();

        println!("{:?}", list);
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// Reads a record from the unencrypted store.  Requires a snapshot password.
async fn read_from_store_command(
    pass: &str,
    rpath: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();

        let data = stronghold.read_from_store(rpath.into()).await.unwrap();

        println!("Data: {:?}", std::str::from_utf8(&data.unwrap()).unwrap());
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// Deletes from insecure store
async fn delete_from_store_command(
    pass: &str,
    rpath: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();

        stronghold.delete_from_store(rpath.into()).await.unwrap();
        stronghold
            .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path. Try writing first.",
        ));
    }

    Ok(())
}

/// Revoke a record.  Data isn't actually deleted until it is garbage collected.  Accepts a password and the record id
/// that you want to revoke.
async fn revoke_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
        stronghold.delete_data(Location::generic(id, id), false).await.unwrap();

        stronghold
            .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first. ",
        ));
    }

    Ok(())
}

/// garbage collect the chain.  Remove any revoked data from the chain.  Requires the password.
async fn garbage_collect_vault_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();

        let location = Location::generic(id, id);
        stronghold
            .garbage_collect(location.vault_path().to_vec())
            .await
            .unwrap();
        let list = stronghold
            .list_hints_and_ids(location.vault_path().to_vec())
            .await
            .unwrap();

        println!("{:?}", list);

        stronghold
            .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first.",
        ));
    }

    Ok(())
}

/// Purge a record from the chain.  Calls revoke and garbage collect in one command.  Requires a password and the record
/// id.
async fn purge_command(
    pass: &str,
    id: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut key = [0u8; 32];
    let salt = [0u8; 32];
    naive_kdf(pass.as_bytes(), &salt, &mut key);

    let snapshot = home_dir()?.join("snapshots").join("commandline.stronghold");

    if snapshot.exists() {
        stronghold
            .read_snapshot(client_path, None, &key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
        let location = Location::generic(id, id);
        stronghold.delete_data(location.clone(), true).await.unwrap();
        let list = stronghold
            .list_hints_and_ids(location.vault_path().to_vec())
            .await
            .unwrap();

        println!("{:?}", list);

        stronghold
            .write_all_to_snapshot(&key.to_vec(), Some("commandline".to_string()), None)
            .await
            .unwrap();
    } else {
        return Err(Box::from(
            "Could not find a snapshot at the home path.  Try writing first.",
        ));
    }
    Ok(())
}

async fn take_ownership_command(
    _password: &str,
    _stronghold: &mut Stronghold,
    _client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    todo!()
}

#[actix::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app = ExampleApp::parse();

    let client_path = app.actor_path.as_bytes().to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(client_path.clone(), vec![]).await?;

    match app.cmds {
        Commands::Encrypt {
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
            )
            .await
        }
        Commands::GarbageCollect { pass, id } => {
            garbage_collect_vault_command(pass.as_str(), id.as_str(), &mut stronghold, client_path).await
        }
        Commands::List { pass, record_path } => {
            list_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path).await
        }
        Commands::Purge { password, id } => {
            purge_command(password.as_str(), id.as_str(), &mut stronghold, client_path).await
        }
        Commands::Read { pass, record_path } => {
            read_from_store_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path).await
        }
        Commands::Revoke { id, password } => {
            revoke_command(password.as_str(), id.as_str(), &mut stronghold, client_path).await
        }
        Commands::Snapshot { path, pass } => {
            snapshot_command(pass.as_str(), path.as_str(), &mut stronghold, client_path).await
        }
        Commands::TakeOwnership { password } => {
            take_ownership_command(password.as_str(), &mut stronghold, client_path).await
        }
        Commands::Write {
            pass,
            record_path,
            plain,
        } => {
            write_to_store_command(
                pass.as_str(),
                plain.as_str(),
                record_path.as_str(),
                &mut stronghold,
                client_path,
            )
            .await
        }
        Commands::Delete { record_path, pass } => {
            delete_from_store_command(pass.as_str(), record_path.as_str(), &mut stronghold, client_path).await
        }
    }?;

    Ok(())
}

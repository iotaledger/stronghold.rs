#![allow(dead_code)]

mod client;
mod connection;
mod crypt;
mod provider;
mod state;

use vault::{Id, Key};

use snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir};

use clap::{load_yaml, App};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use crate::{client::Client, provider::Provider};

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();

    let snapshot = get_snapshot_path();

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if snapshot.exists() {
                    let snapshot = get_snapshot_path();
                    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                    client.perform_gc();
                    client.create_entry(plain.as_bytes().to_vec());

                    let snapshot = get_snapshot_path();
                    serialize_to_snapshot(&snapshot, pass, client);
                } else {
                    let key = Key::<Provider>::random().unwrap();
                    let id = Id::random::<Provider>().unwrap();
                    let client = Client::create_chain(key, id);
                    client.create_entry(plain.as_bytes().to_vec());

                    let snapshot = get_snapshot_path();
                    serialize_to_snapshot(&snapshot, pass, client);
                }
            };
        };
    }

    if let Some(matches) = matches.subcommand_matches("snapshot") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref path) = matches.value_of("path") {
                let path = Path::new(path);

                let client: Client<Provider> = deserialize_from_snapshot(&path.to_path_buf(), pass);

                client.perform_gc();

                let new_path = path.parent().unwrap().join("recomputed.snapshot");
                serialize_to_snapshot(&new_path, pass, client);
            }
        }
    }

    if let Some(matches) = matches.subcommand_matches("list") {
        if let Some(ref pass) = matches.value_of("password") {
            let snapshot = get_snapshot_path();
            let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

            client.perform_gc();

            client.list_ids();

            let snapshot = get_snapshot_path();
            serialize_to_snapshot(&snapshot, pass, client);
        }
    }
}

fn get_snapshot_path() -> PathBuf {
    let path = snapshot_dir().expect("Unable to get the snapshot directory");

    let snapshot = path.join("backup.snapshot");

    snapshot
}

fn deserialize_from_snapshot(snapshot: &PathBuf, pass: &str) -> Client<Provider> {
    let mut buffer = Vec::new();

    let mut file = OpenOptions::new().read(true).open(snapshot).unwrap();

    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes()).unwrap();

    bincode::deserialize(&buffer[..]).expect("Unable to deserialize data")
}

fn serialize_to_snapshot(snapshot: &PathBuf, pass: &str, client: Client<Provider>) {
    let mut file = OpenOptions::new().write(true).open(snapshot).unwrap();

    let data: Vec<u8> = bincode::serialize(&client).unwrap();
    encrypt_snapshot(data, &mut file, pass.as_bytes()).unwrap();
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn test_bincode() {
//         let pass = "test";
//         let key = Key::<Provider>::random().unwrap();
//         let id = Id::random::<Provider>().unwrap();
//         let client = Client::create_chain(key, id);
//         client.create_entry("test".as_bytes().to_vec());
//         let mut buffer: Vec<u8> = Vec::new();

//         let data: Vec<u8> = bincode::serialize(&client).unwrap();
//         println!("{:?}", &data);

//         let mut write = OpenOptions::new()
//             .create(true)
//             .write(true)
//             .open("test")
//             .unwrap();

//         encrypt_snapshot(data, &mut write, pass.as_bytes()).unwrap();

//         let mut read = OpenOptions::new().read(true).open("test").unwrap();

//         decrypt_snapshot(&mut read, &mut buffer, pass.as_bytes()).unwrap();

//         let incoming_client = bincode::deserialize::<Client<Provider>>(&buffer[..]).unwrap();

//         incoming_client.create_entry("another test".as_bytes().to_vec());
//     }
// }

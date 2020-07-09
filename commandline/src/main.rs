#![allow(dead_code)]

mod client;
mod connection;
mod crypt;
mod provider;
mod state;

use vault::{Id, Key};

use snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir};
use vault::Base64Decodable;

use clap::{load_yaml, App};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{client::Client, provider::Provider, state::State};

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
                    let key = Key::<Provider>::random().expect("Unable to generate a new key");
                    let id = Id::random::<Provider>().expect("Unable to generate a new id");
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

    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let snapshot = get_snapshot_path();
                let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                client.perform_gc();

                let id = Vec::from_base64(id.as_bytes())
                    .expect("couldn't convert the id to from base64");
                let id = Id::load(&id).expect("Couldn't build a new Id");

                client.read_entry_by_id(id);

                let snapshot = get_snapshot_path();
                serialize_to_snapshot(&snapshot, pass, client);
            }
        }
    }
}

fn get_snapshot_path() -> PathBuf {
    let path = snapshot_dir().expect("Unable to get the snapshot directory");

    let snapshot = path.join("backup.snapshot");

    snapshot
}

fn deserialize_from_snapshot(snapshot: &PathBuf, pass: &str) -> Client<Provider> {
    upload_state();
    let mut buffer = Vec::new();

    let mut file = OpenOptions::new().read(true).open(snapshot).expect(
        "Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.",
    );

    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes())
        .expect("unable to decrypt the snapshot");

    bincode::deserialize(&buffer[..]).expect("Unable to deserialize data")
}

fn serialize_to_snapshot(snapshot: &PathBuf, pass: &str, client: Client<Provider>) {
    offload_state();
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(snapshot)
        .expect(
        "Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.",
    );

    let data: Vec<u8> = bincode::serialize(&client).expect("Couldn't serialize the client data");
    encrypt_snapshot(data, &mut file, pass.as_bytes()).expect("Couldn't write to the snapshot");
}

fn offload_state() {
    let path = snapshot_dir().unwrap().join("map_data");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .expect("Unable to access map data");

    let data: Vec<u8> = bincode::serialize(&State::offload_data()).expect("couldn't serialize map");

    file.write_all(&data).expect("unable to write to map file");
}

fn upload_state() {
    let path = snapshot_dir().unwrap().join("map_data");
    let mut buffer: Vec<u8> = Vec::new();

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("Unable to access map data");

    file.read_to_end(&mut buffer).expect("unable to read data");

    let map: HashMap<Vec<u8>, Vec<u8>> =
        bincode::deserialize(&buffer[..]).expect("unable to deserialize map");

    State::upload_data(map);
}

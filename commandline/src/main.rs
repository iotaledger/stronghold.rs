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

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use crate::{
    client::{Client, Snapshot},
    provider::Provider,
};

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
    let mut buffer = Vec::new();

    let mut file = OpenOptions::new().read(true).open(snapshot).expect(
        "Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.",
    );

    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes())
        .expect("unable to decrypt the snapshot");

    let snap: Snapshot<Provider> =
        bincode::deserialize(&buffer[..]).expect("Unable to deserialize data");

    let (id, db) = snap.offload();

    let client = Client::<Provider>::new(id, db);

    client
}

fn serialize_to_snapshot(snapshot: &PathBuf, pass: &str, client: Client<Provider>) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(snapshot)
        .expect(
        "Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.",
    );

    let snap: Snapshot<Provider> = Snapshot::new(client.id, client.db);

    let data: Vec<u8> = bincode::serialize(&snap).expect("Couldn't serialize the client data");
    encrypt_snapshot(data, &mut file, pass.as_bytes()).expect("Couldn't write to the snapshot");
}

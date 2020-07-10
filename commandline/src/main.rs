#![allow(dead_code)]

mod client;
mod connection;
mod crypt;
mod provider;
mod snap;
mod state;

use crate::{
    snap::{deserialize_from_snapshot, get_snapshot_path, serialize_to_snapshot},
    {client::Client, provider::Provider},
};

use vault::{Base64Decodable, Id, Key};

use clap::{load_yaml, App, ArgMatches};

use std::path::Path;

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

fn encrypt_command(matches: &ArgMatches) {
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
}

fn snapshot_command(matches: &ArgMatches) {
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
}

fn list_command(matches: &ArgMatches) {
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

fn read_command(matches: &ArgMatches) {
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

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();

    encrypt_command(&matches);
    snapshot_command(&matches);
    read_command(&matches);
    list_command(&matches);
}

mod client;
mod connection;
mod provider;
mod snap;
mod state;

use crate::{
    client::Client,
    provider::Provider,
    snap::{deserialize_from_snapshot, get_snapshot_path, serialize_to_snapshot},
};

use vault::{Base64Decodable, Id, Key};

use clap::{load_yaml, App, ArgMatches};

use std::path::Path;

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
fn encrypt_command(matches: &ArgMatches) {
    let snapshot = get_snapshot_path();

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if snapshot.exists() {
                    let snapshot = get_snapshot_path();
                    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                    client.create_record(plain.as_bytes().to_vec());

                    let snapshot = get_snapshot_path();
                    serialize_to_snapshot(&snapshot, pass, client);
                } else {
                    let key = Key::<Provider>::random().expect("Unable to generate a new key");
                    let id = Id::random::<Provider>().expect("Unable to generate a new id");
                    let client = Client::create_chain(key, id);
                    client.create_record(plain.as_bytes().to_vec());

                    let snapshot = get_snapshot_path();
                    serialize_to_snapshot(&snapshot, pass, client);
                }
            };
        };
    }
}

// handle the snapshot command.
fn snapshot_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("snapshot") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref path) = matches.value_of("path") {
                let path = Path::new(path);

                let client: Client<Provider> = deserialize_from_snapshot(&path.to_path_buf(), pass);

                let new_path = path.parent().unwrap().join("recomputed.snapshot");
                serialize_to_snapshot(&new_path, pass, client);
            }
        }
    }
}

// handle the list command.
fn list_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("list") {
        if let Some(ref pass) = matches.value_of("password") {
            let snapshot = get_snapshot_path();
            let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

            client.list_ids();

            let snapshot = get_snapshot_path();
            serialize_to_snapshot(&snapshot, pass, client);
        }
    }
}

// handle the read command.
fn read_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let snapshot = get_snapshot_path();
                let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                let id = Vec::from_base64(id.as_bytes()).expect("couldn't convert the id to from base64");
                let id = Id::load(&id).expect("Couldn't build a new Id");

                client.read_record_by_id(id);

                let snapshot = get_snapshot_path();
                serialize_to_snapshot(&snapshot, pass, client);
            }
        }
    }
}

// create a record with a revoke transaction.  Data isn't actually deleted until it is garbage collected.
fn revoke_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("revoke") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let snapshot = get_snapshot_path();
                let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                let id = Vec::from_base64(id.as_bytes()).expect("couldn't convert the id to from base64");
                let id = Id::load(&id).expect("Couldn't build a new Id");

                client.revoke_record_by_id(id);

                let snapshot = get_snapshot_path();
                serialize_to_snapshot(&snapshot, pass, client);
            }
        }
    }
}

// garbage collect the chain.  Remove any revoked data from the chain.
fn garbage_collect_vault_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("garbage_collect") {
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

// Take ownership of an existing chain. Requires that the new chain owner knows the old key to unlock the data.
fn take_ownership_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("take_ownership") {
        if let Some(ref pass) = matches.value_of("password") {
            let new_id = Id::random::<Provider>().expect("Unable to generate a new id");

            let snapshot = get_snapshot_path();
            let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);
            let new_client: Client<Provider> = Client::create_chain(client.db.key, new_id);

            new_client.take_ownership(client.id);

            println!("Old owner id: {:?}\nNew owner id: {:?}", client.id, new_client.id);

            let snapshot = get_snapshot_path();
            serialize_to_snapshot(&snapshot, pass, new_client);
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
    revoke_command(&matches);
    garbage_collect_vault_command(&matches);
    take_ownership_command(&matches);
}

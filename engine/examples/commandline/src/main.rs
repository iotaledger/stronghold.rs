// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod client;
mod connection;
mod msg_handler;
mod provider;
mod snap;
mod state;

use crate::msg_handler::Handler;
use crate::{
    client::Client,
    provider::Provider,
    snap::{deserialize_from_snapshot, get_snapshot_path, serialize_to_snapshot},
};

use engine::vault::{Base64Decodable, RecordId, Key};

use clap::{load_yaml, App, ArgMatches};

use std::{
    path::Path,
    convert::TryFrom,
};

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
                let client: Client<Provider> = if snapshot.exists() {
                    let snapshot = get_snapshot_path();
                    deserialize_from_snapshot(&snapshot, pass)
                } else {
                    let key = Key::<Provider>::random().expect("Unable to generate a new key");
                    Client::new(key)
                };

                // TODO: optionally get from argument
                let id = RecordId::random::<Provider>().expect("Unable to generate a new id");

                client.write(id, plain.as_bytes().to_vec());

                let snapshot = get_snapshot_path();
                serialize_to_snapshot(&snapshot, pass, client);
                println!("{}", id);
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

            if matches.is_present("all") {
                client.list_all_ids();
            } else {
                client.list_ids();
            }
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
                let id = RecordId::try_from(id).expect("Couldn't build a new Id");

                client.read_record_by_id(id);
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
                let id = RecordId::try_from(id).expect("Couldn't build a new Id");

                client.revoke_record(id);

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

// Purge a record from the chain: revoke and then garbage collect.
fn purge_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("purge") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref id) = matches.value_of("id") {
                let snapshot = get_snapshot_path();
                let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

                let id = Vec::from_base64(id.as_bytes()).expect("couldn't convert the id to from base64");
                let id = RecordId::try_from(id).expect("Couldn't build a new Id");

                client.revoke_record(id);
                serialize_to_snapshot(&get_snapshot_path(), pass, client);

                let client = deserialize_from_snapshot(&snapshot, pass);
                client.perform_gc();
                assert!(client.db.take(|db| db.all().find(|i| i == &id).is_none()));
                serialize_to_snapshot(&get_snapshot_path(), pass, client);
            }
        }
    }
}

// Put a record into the mailbox
fn put_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("put_mailbox") {
        if let Some(mail_id) = matches
            .value_of("mailbox_id")
            .and_then(|id_arg| PeerId::from_str(id_arg.as_str()).ok())
        {
            if let Some(mail_addr) = matches
                .value_of("mailbox_addr")
                .and_then(|addr_arg| Multiaddr::from_str(&*addr_arg).ok())
            {
                if let Some(key) = matches.value_of("key") {
                    if let Some(value) = matches.value_of("value") {
                        let local_keys = Keypair::generate_ed25519();
                        let local_peer_id = PeerId::from(local_keys.public());
                        let timeout = matches.value_of("timeout").map(|timeout| timeout.parse::<u64>());
                        let behaviour = P2PNetworkBehaviour::new(local_peer_id, timeout, Handler);
                        let p2p = P2P::new(behaviour, local_keys, None, (mail_id, mail_addr));
                        let request_id = p2p.put_record_mailbox(key, value, None, None);
                        if request_id.is_ok() {
                            println("Successfully send record to mailbox");
                            return;
                        }
                    }
                }
            }
        }
    }
    eprintln("Could not send record to mailbox");
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
    purge_command(&matches);
}

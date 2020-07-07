use commandline::{Env, Provider};

mod client;

use client::Client;

use std::collections::HashMap;
use vault::{DBView, Id, Key, ListResult, ReadResult};

fn main() {
    let key = Key::<Provider>::random().expect("Failed to generate a random key");
    let id = Id::random::<Provider>().expect("Failed to generate random ID");

    println!(
        "key {:?}, id {:?}",
        String::from_utf8_lossy(key.bytes()),
        id
    );
}

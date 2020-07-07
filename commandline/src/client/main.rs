mod client;

use client::Client;

use clap::{load_yaml, App};

fn main() {
    // let key = Key::<Provider>::random().expect("Failed to generate a random key");
    // let id = Id::random::<Provider>().expect("Failed to generate random ID");
    // Client::<Provider>::init_entry(&key, id);
    // let client = Client::<Provider>::start(key.clone(), id);

    // client.create_entry(b"some data");

    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
}

mod client;
mod connection;
mod crypt;
mod provider;
mod state;

use vault::{Id, Key};

use snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir};

use clap::{load_yaml, App};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::{
    client::{Client, Db},
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
                    let mut buffer = Vec::new();
                    let snapshot = get_snapshot_path();
                    let mut file = OpenOptions::new().read(true).open(snapshot).unwrap();

                    decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes()).unwrap();

                    let client: Client<Provider> =
                        bincode::deserialize(&buffer[..]).expect("Unable to deserialize data");

                    client.perform_gc();
                    client.create_entry(plain.as_bytes().to_vec());

                    let snapshot = get_snapshot_path();
                    let mut file = OpenOptions::new().write(true).open(snapshot).unwrap();

                    let data: Vec<u8> = bincode::serialize(&client).unwrap();
                    encrypt_snapshot(data, &mut file, pass.as_bytes()).unwrap();
                } else {
                    let key = Key::<Provider>::random().unwrap();
                    let id = Id::random::<Provider>().unwrap();
                    let client = Client::create_chain(key, id);
                    client.create_entry(plain.as_bytes().to_vec());

                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(snapshot)
                        .unwrap();

                    let data: Vec<u8> = bincode::serialize(&client).unwrap();
                    encrypt_snapshot(data, &mut file, pass.as_bytes()).unwrap();
                }
            };
        };
    }

    if let Some(matches) = matches.subcommand_matches("snapshot") {
        if let Some(ref pass) = matches.value_of("password") {
            if let Some(ref path) = matches.value_of("path") {
                let mut buffer: Vec<u8> = Vec::new();
                let path = Path::new(path);

                let mut file = OpenOptions::new().read(true).open(path).unwrap();

                decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes()).unwrap();

                let client: Client<Provider> =
                    bincode::deserialize(&buffer[..]).expect("Unable to deserialize data");

                client.perform_gc();

                let new_path = path.parent().unwrap().join("recomputed.snapshot");
                let mut file = OpenOptions::new().write(true).open(new_path).unwrap();

                let data: Vec<u8> = bincode::serialize(&client).unwrap();
                encrypt_snapshot(data, &mut file, pass.as_bytes()).unwrap();
            }
        }
    }
}

fn get_snapshot_path() -> PathBuf {
    let path = snapshot_dir().expect("Unable to get the snapshot directory");

    let snapshot = path.join("backup.snapshot");

    snapshot
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

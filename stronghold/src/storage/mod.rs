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

mod client;
mod connection;
mod provider;
mod snap;
mod state;

use client::Client;
use provider::Provider;
use snap::{deserialize_from_snapshot, get_snapshot_path, serialize_to_snapshot};

use engine::{vault};

pub use vault::{Base64Decodable, Id, Key};

use std::path::Path;

// handle the encryption command.
pub fn exists() -> bool {
    let snapshot = get_snapshot_path();
    snapshot.exists()
}

pub fn encrypt(plain: &str, pass: &str) {
    let snapshot = get_snapshot_path();

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
}

// handle the snapshot command.
pub fn snapshot(path: &str, pass: &str) {
    let path = Path::new(path);

    let client: Client<Provider> = deserialize_from_snapshot(&path.to_path_buf(), pass);

    let new_path = path.parent().unwrap().join("recomputed.snapshot");
    serialize_to_snapshot(&new_path, pass, client);
}

// handle the list command.
pub fn list(pass: &str) -> Vec<Id> {
    let snapshot = get_snapshot_path();
    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

    let ids = client.list_ids();

    let snapshot = get_snapshot_path();
    serialize_to_snapshot(&snapshot, pass, client);

    ids
}

// handle the read command.
pub fn read(id: Id, pass: &str) -> String {
    let snapshot = get_snapshot_path();
    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

    let id = Vec::from_base64(id).expect("couldn't convert the id to from base64");
    let id = Id::load(&id).expect("Couldn't build a new Id");

    let record = client.read_record_by_id(id);

    let snapshot = get_snapshot_path();
    serialize_to_snapshot(&snapshot, pass, client);

    record
}

// create a record with a revoke transaction.  Data isn't actually deleted until it is garbage collected.
pub fn revoke(id: Id, pass: &str) {
    let snapshot = get_snapshot_path();
    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

    let id = Vec::from_base64(id).expect("couldn't convert the id to from base64");
    let id = Id::load(&id).expect("Couldn't build a new Id");

    client.revoke_record_by_id(id);

    let snapshot = get_snapshot_path();
    serialize_to_snapshot(&snapshot, pass, client);
}

// garbage collect the chain.  Remove any revoked data from the chain.
pub fn garbage_collect_vault(pass: &str) {
    let snapshot = get_snapshot_path();
    let client: Client<Provider> = deserialize_from_snapshot(&snapshot, pass);

    client.perform_gc();
    client.list_ids();

    let snapshot = get_snapshot_path();
    serialize_to_snapshot(&snapshot, pass, client);
}

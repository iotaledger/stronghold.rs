// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// macro to print status
macro_rules! print_status {
    ($data:expr) => {{
        use std::io::{self, Write};
        let mut stdout = io::stdout();
        let _ = stdout.write($data);
        let _ = stdout.flush();
    }};
}

// creates error description with file and line.
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
}

mod client;
mod connection;
mod crypt;
mod env;
mod skynet;
mod worker;

use crate::{client::Client, crypt::Provider, env::Env, skynet::Machine, worker::Worker};
use std::collections::HashMap;
use vault::{DBView, Id, Key, ListResult, ReadResult};

fn main() {
    // prepare key and ids
    let key = Key::<Provider>::random().expect("failed to generate random key");
    let ids: Vec<Id> = (0..Env::client_count())
        .map(|_| Id::random::<Provider>().expect("Failed to generate random ID"))
        .collect();

    // print info.
    eprintln! {
        "Spraying fuzz [{}: {}, {}: {}, {}: {}, {}: {}]...",
        "Number of Clients", Env::client_count(),
        "Error rate", Env::error_rate(),
        "Verification rate", Env::verify_number(),
        "Retry delay", Env::retry_delay(),
    };

    // start fuzzing
    ids.iter().for_each(|id| Client::<Provider>::create_chain(&key, *id));

    loop {
        // start worker
        Worker::start(key.clone());

        // start iterations
        let join_handles: Vec<_> = ids
            .iter()
            .map(|i| Client::<Provider>::start(Env::verify_number(), key.clone(), *i))
            .collect();

        join_handles
            .into_iter()
            .for_each(|th| assert!(th.join().is_ok(), "Thread panicked"));

        // generate machine to assimilate chains
        let first = ids.get(0).expect(line_error!());
        Machine::new(*first, key.clone()).assimilate_rand(&ids[1..]);
        print_status!(b"^");

        // lock the vault
        let (_store, _shadow) = (Env::storage(), Env::shadow_storage());
        let (store, shadow) = (
            _store.read().expect(line_error!()),
            _shadow.read().expect(line_error!()),
        );

        // load vault and gather all records.
        let list_res = ListResult::new(store.keys().cloned().collect());
        let view = DBView::load(key.clone(), list_res).expect(line_error!());

        let mut records = HashMap::new();
        for (id, _) in view.records() {
            // read the data.
            let read = view.reader().prepare_read(id).expect(line_error!());
            let data = store.get(read.id()).expect(line_error!()).clone();

            // open an record
            let record = view
                .reader()
                .read(ReadResult::new(read.into(), data))
                .expect(line_error!());
            records.insert(id, record);
        }

        let shadow_records: HashMap<_, _> = shadow
            .iter()
            .map(|(id, data)| (Id::load(id).expect(line_error!()), data.clone()))
            .collect();

        // compare real to shadow records.
        assert_eq!(records, shadow_records, "Real and shadow vault payloads are not equal");
        print_status!(b"##\n");
    }
}

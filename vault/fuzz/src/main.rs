macro_rules! print_status {
    ($data:expr) => {{
        use std::io::{self, Write};
        let mut stdout = io::stdout();
        let _ = stdout.write($data);
        let _ = stdout.flush();
    }};
}

macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
}

mod client;
mod crypt;
mod env;
mod remote;
mod skynet;
mod worker;

use crate::{client::Client, crypt::Provider, env::Env, skynet::Machine, worker::Worker};
use std::collections::HashMap;
use vault::{DBView, Id, Key, ListResult, ReadResult};

fn main() {
    let key = Key::<Provider>::random().expect("failed to generate random key");
    let ids: Vec<Id> = (0..Env::client_count())
        .map(|_| Id::random::<Provider>().expect("Failed to generate random ID"))
        .collect();

    eprintln! {
        "Spraying fuzz [{}: {}, {}: {}, {}: {}, {}: {}]...",
        "client_counter", Env::client_count(),
        "Error_probability", Env::error_probability(),
        "Verify_internal", Env::verify_interval(),
        "Retry_delay_ms", Env::retry_delay_ms(),
    };

    ids.iter()
        .for_each(|id| Client::<Provider>::create_chain(&key, *id));

    loop {
        Worker::start(key.clone());

        let join_handles: Vec<_> = ids
            .iter()
            .map(|i| Client::<Provider>::start(Env::verify_interval(), key.clone(), *i))
            .collect();

        join_handles
            .into_iter()
            .for_each(|th| assert!(th.join().is_ok(), "Thread panicked"));

        let first = ids.get(0).expect(line_error!());
        Machine::new(*first, key.clone()).assimilate_rand(&ids[1..]);
        print_status!(b"@");

        let (_store, _shadow) = (Env::storage(), Env::shadow_storage());
        let (store, shadow) = (
            _store.read().expect(line_error!()),
            _shadow.read().expect(line_error!()),
        );

        let list_res = ListResult::new(store.keys().cloned().collect());
        let view = DBView::load(key.clone(), list_res).expect(line_error!());

        let mut entries = HashMap::new();
        for (id, _) in view.entries() {
            let read = view.reader().prepare_read(id).expect(line_error!());
            let data = store.get(read.id()).expect(line_error!()).clone();

            let entry = view
                .reader()
                .read(ReadResult::new(read.into(), data))
                .expect(line_error!());
            entries.insert(id, entry);
        }

        let shadow_entries: HashMap<_, _> = shadow
            .iter()
            .map(|(id, data)| (Id::load(id).expect(line_error!()), data.clone()))
            .collect();

        assert_eq!(
            entries, shadow_entries,
            "Real and shadow database payloads are not equal"
        );
        print_status!(b"=\n");
    }
}

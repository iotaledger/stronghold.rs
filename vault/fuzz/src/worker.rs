use crate::env::Env;

use vault::{BoxProvider, DBView, Id, Key, ListResult, ReadResult};

use std::{collections::HashMap, thread, time::Duration};

// a worker
pub struct Worker<P: BoxProvider + Send + 'static> {
    key: Key<P>,
    state: HashMap<Id, u64>,
}

impl<P: BoxProvider + Send + 'static> Worker<P> {
    // start the worker
    pub fn start(key: Key<P>) {
        let inst = Self {
            key,
            state: HashMap::new(),
        };
        thread::spawn(move || inst.work());
    }

    // do the work
    fn work(mut self) {
        loop {
            // clone storage and load the vault
            let storage = Env::storage().read().expect(line_error!()).clone();
            let ids = ListResult::new(storage.keys().cloned().collect());
            let view = DBView::load(self.key.clone(), ids).expect(line_error!());

            // ensure that the vault is not older than the previous one.
            view.not_older_than(&self.state).expect(line_error!());
            self.state = view.chain_ctrs();

            // read each entry.
            let reader = view.reader();
            for (id, _) in view.entries() {
                let req = reader.prepare_read(id).expect(line_error!());
                let data = storage.get(req.id()).expect(line_error!());
                let _payload = reader
                    .read(ReadResult::new(req.into(), data.clone()))
                    .expect(line_error!());
            }

            // print status and sleep
            print_status!(b"|");
            thread::sleep(Duration::from_secs(1));
        }
    }
}

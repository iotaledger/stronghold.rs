#![no_main]

use rand::Rng;
use vault::{DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest};

use libfuzzer_sys::fuzz_target;

mod provider;

use provider::Provider;

pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
    bs.into()
}

// Requires Linux, MacOS or WSL to compile.  Requires the nightly toolchain and cargo fuzz tool.
fuzz_target!(|data: &[u8]| {
    let mut writes: Vec<ReadResult> = vec![];

    let k: Key<Provider> = Key::random().expect("unable to generate key");
    let v0 = DBView::load(k.clone(), writes.iter()).expect("unable to load DBView");

    let id = RecordId::random::<Provider>().expect("unable to generate record id");
    let mut w = v0.writer(id);

    writes.push(write_to_read(&w.truncate().expect("unable to truncate record")));
    let hint = record_hint();
    let wrs = w.write(&data, hint).expect("unable to write data");

    wrs.iter().for_each(|w| writes.push(write_to_read(w)));

    let v1 = DBView::load(k, writes.iter()).expect("unable to load DBView");

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.records().count(), 1);
    assert_eq!(v1.absolute_balance(), (2, 2));
    assert_eq!(v1.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    assert_eq!(
        v1.reader().prepare_read(&id).expect("unable to prepare_read"),
        PreparedRead::CacheHit(data.to_vec())
    );
});

fn write_to_read(wr: &WriteRequest) -> ReadResult {
    ReadResult::new(wr.kind(), wr.id(), wr.data())
}

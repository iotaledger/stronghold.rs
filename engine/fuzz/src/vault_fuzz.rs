// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use engine::vault::{DbView, Key, RecordHint, RecordId, VaultId};
use rand::Rng;

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
    let mut view: DbView<Provider> = DbView::new();

    let key0 = Key::random().unwrap();
    let vid0 = VaultId::random::<Provider>().unwrap();
    let rid0 = RecordId::random::<Provider>().unwrap();

    // init vaults.
    view.init_vault(&key0, vid0).unwrap();
    // write to vault0 and record0
    view.write(&key0, vid0, rid0, data, RecordHint::new(b"hint").unwrap())
        .unwrap();

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 1);

    // read from vault0 and record0
    view.get_guard(&key0, vid0, rid0, |g| {
        assert_eq!(data, &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 1);

    // garbage collect vid0.
    view.garbage_collect_vault(&key0, vid0).unwrap();

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 1);

    let b = view.contains_record(&key0, vid0, rid0);

    assert!(b);

    // read vid0 and rid0.
    view.get_guard(&key0, vid0, rid0, |g| {
        assert_eq!(data, &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    let key0 = Key::random().unwrap();
    let vid0 = VaultId::random::<Provider>().unwrap();
    let rid0 = RecordId::random::<Provider>().unwrap();

    let key1 = Key::random().unwrap();
    let vid1 = VaultId::random::<Provider>().unwrap();
    let rid1 = RecordId::random::<Provider>().unwrap();

    // Write data into vid0/rid0
    view.write(&key0, vid0, rid0, b"test", RecordHint::new(b"hint").unwrap())
        .unwrap();

    // execute a procedure and put the result into a new record
    view.exec_proc(
        &key0,
        vid0,
        rid0,
        &key1,
        vid1,
        rid1,
        RecordHint::new(b"tester").unwrap(),
        |guard| {
            let data = guard.borrow();
            let mut ret = Vec::new();

            ret.extend(data.iter());
            ret.extend(data.iter());

            Ok(ret)
        },
    )
    .unwrap();

    // read vid0 and rid0.
    view.get_guard(&key0, vid0, rid0, |g| {
        assert_eq!(b"test", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read vid1 and rid1.
    view.get_guard(&key1, vid1, rid1, |g| {
        assert_eq!(b"testtest", &(*g.borrow()));

        Ok(())
    })
    .unwrap();
});

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod utils;
use std::convert::Infallible;

use utils::provider::Provider;

use engine::vault::{DbView, Key, RecordHint, RecordId, VaultId};

#[test]
fn test_vaults() {
    let mut view: DbView<Provider> = DbView::new();

    let key0 = Key::random();
    let vid0 = VaultId::random::<Provider>().unwrap();
    let rid0 = RecordId::random::<Provider>().unwrap();
    let rid01 = RecordId::random::<Provider>().unwrap();

    let key1 = Key::random();
    let vid1 = VaultId::random::<Provider>().unwrap();
    let rid1 = RecordId::random::<Provider>().unwrap();

    // init two vaults.
    view.init_vault(&key0, vid0);
    view.init_vault(&key1, vid1);
    // write to vault0 and record0
    view.write(&key0, vid0, rid0, b"test0", RecordHint::new(b"hint").unwrap())
        .unwrap();
    // write to vault0 and record01
    view.write(&key0, vid0, rid01, b"test01", RecordHint::new(b"hint").unwrap())
        .unwrap();
    // write to vault1 and record1
    view.write(&key1, vid1, rid1, b"test1", RecordHint::new(b"hint").unwrap())
        .unwrap();

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 2);

    // read from vault0 and record0
    view.get_guard::<Infallible, _>(&key0, vid0, rid0, |g| {
        assert_eq!(b"test0", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read from vault0 and record01
    view.get_guard::<Infallible, _>(&key0, vid0, rid01, |g| {
        assert_eq!(b"test01", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read from vault1 and record1
    view.get_guard::<Infallible, _>(&key1, vid1, rid1, |g| {
        assert_eq!(b"test1", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // revoke records rid01 and rid1
    view.revoke_record(&key0, vid0, rid01).unwrap();
    view.revoke_record(&key1, vid1, rid1).unwrap();

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 1);

    // garbage collect vid0.
    view.garbage_collect_vault(&key0, vid0);

    let list0 = view.list_hints_and_ids(&key0, vid0);

    assert_eq!(list0.len(), 1);

    let b = view.contains_record(&key0, vid0, rid0);

    assert!(b);

    let b = view.contains_record(&key0, vid0, rid01);

    assert!(!b);

    // read vid0 and rid0.
    view.get_guard::<Infallible, _>(&key0, vid0, rid0, |g| {
        assert_eq!(b"test0", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    let key0 = Key::random();
    let vid0 = VaultId::random::<Provider>().unwrap();
    let rid0 = RecordId::random::<Provider>().unwrap();

    let key1 = Key::random();
    let vid1 = VaultId::random::<Provider>().unwrap();
    let rid1 = RecordId::random::<Provider>().unwrap();

    // Write data into vid0/rid0
    view.write(&key0, vid0, rid0, b"test", RecordHint::new(b"hint").unwrap())
        .unwrap();

    // execute a procedure and put the result into a new record
    view.exec_proc::<Infallible, _>(
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
    view.get_guard::<Infallible, _>(&key0, vid0, rid0, |g| {
        assert_eq!(b"test", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read vid1 and rid1.
    view.get_guard::<Infallible, _>(&key1, vid1, rid1, |g| {
        assert_eq!(b"testtest", &(*g.borrow()));

        Ok(())
    })
    .unwrap();
}

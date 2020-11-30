// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod utils;
use utils::provider::Provider;

mod fresh;

use vault::{DBView, Encrypt, Key, Kind, PreparedRead, ReadResult, RecordId, Result, WriteRequest};

use std::{collections::HashMap, iter::empty};

fn write_to_read(wr: &WriteRequest) -> ReadResult {
    ReadResult::new(wr.kind(), wr.id(), wr.data())
}

#[test]
fn test_empty() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v = DBView::load(k, empty::<ReadResult>())?;

    assert_eq!(v.all().len(), 0);
    assert_eq!(v.absolute_balance(), (0, 0));
    assert_eq!(v.chain_ctrs(), HashMap::new());
    assert_eq!(v.gc().len(), 0);

    Ok(())
}

#[test]
fn test_truncate() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    writes.push(v0.writer(id).truncate()?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.absolute_balance(), (1, 1));
    assert_eq!(v1.chain_ctrs(), vec![(id, 0u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::RecordIsEmpty);

    Ok(())
}

#[test]
fn test_read_non_existent_record() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v = DBView::load(k.clone(), empty::<ReadResult>())?;

    let id = RecordId::random::<Provider>()?;
    assert_eq!(v.reader().prepare_read(&id)?, PreparedRead::NoSuchRecord);

    Ok(())
}

#[test]
fn test_write_cache_hit() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let data = fresh::data();
    let hint = fresh::record_hint();
    writes.append(&mut w.write(&data, hint)?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.records().collect::<Vec<_>>().len(), 1);
    assert_eq!(v1.absolute_balance(), (2, 2));
    assert_eq!(v1.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::CacheHit(data));

    Ok(())
}

#[test]
fn test_write_cache_miss() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let data = fresh::data();
    let hint = fresh::record_hint();
    let (bid, blob) = match w.write(&data, hint)?.as_slice() {
        [w0, w1] => {
            assert_eq!(w0.kind(), Kind::Transaction);
            writes.push(w0.clone());

            assert_eq!(w1.kind(), Kind::Blob);
            (w1.id().to_vec(), w1.data().to_vec())
        }
        ws => panic!("{} unexpected writes", ws.len()),
    };

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    let r = v1.reader();
    let res = match r.prepare_read(&id)? {
        PreparedRead::CacheMiss(req) => {
            assert_eq!(req.id(), bid.as_slice());
            req.result(blob)
        }
        x => panic!("unexpected value: {:?}", x),
    };

    assert_eq!(r.read(res)?, data);

    Ok(())
}

#[test]
fn test_write_twice() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let data0 = fresh::data();
    let data1 = fresh::data();
    let hint = fresh::record_hint();
    writes.append(&mut w.write(&data0, hint)?);
    writes.append(&mut w.write(&data1, hint)?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.records().collect::<Vec<_>>().len(), 1);
    assert_eq!(v1.absolute_balance(), (2, 3));
    assert_eq!(v1.chain_ctrs(), vec![(id, 2u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 1);

    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::CacheHit(data1));

    Ok(())
}

#[test]
fn test_rekove() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    writes.push(v0.writer(id).truncate()?);

    let v1 = DBView::load(k.clone(), writes.iter().map(write_to_read))?;
    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::RecordIsEmpty);
    writes.push(v1.writer(id).revoke()?);

    let v2 = DBView::load(k, writes.iter().map(write_to_read))?;
    assert_eq!(v2.reader().prepare_read(&id)?, PreparedRead::NoSuchRecord);

    assert_eq!(v2.all().len(), 1);
    assert_eq!(v2.records().collect::<Vec<_>>().len(), 0);
    assert_eq!(v2.absolute_balance(), (0, 2));
    assert_eq!(v2.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v2.gc().len(), 2);

    Ok(())
}

#[test]
fn test_rekove_without_reload() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    writes.push(w.revoke()?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;
    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::NoSuchRecord);

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.records().collect::<Vec<_>>().len(), 0);
    assert_eq!(v1.absolute_balance(), (0, 2));
    assert_eq!(v1.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 2);

    Ok(())
}

#[test]
fn test_rekove_then_write() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    writes.push(w.revoke()?);
    let data = fresh::data();
    let hint = fresh::record_hint();
    writes.append(&mut w.write(&data, hint)?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;
    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::CacheHit(data));

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.records().collect::<Vec<_>>().len(), 1);
    assert_eq!(v1.absolute_balance(), (2, 3));
    assert_eq!(v1.chain_ctrs(), vec![(id, 2u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 1);

    Ok(())
}

#[test]
#[ignore = "not yet implemented: we need some kind of checksum in the data transaction to protect against this case: when the users key is compromised"]
fn test_ensure_authenticty_of_blob() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let hint = fresh::record_hint();
    let bid = match w.write(&fresh::data(), hint)?.as_slice() {
        [w0, w1] => {
            assert_eq!(w0.kind(), Kind::Transaction);
            writes.push(w0.clone());

            assert_eq!(w1.kind(), Kind::Blob);
            w1.id().to_vec()
        }
        ws => panic!("{} unexpected writes", ws.len()),
    };

    let v1 = DBView::load(k.clone(), writes.iter().map(write_to_read))?;

    let r = v1.reader();
    let res = match r.prepare_read(&id)? {
        PreparedRead::CacheMiss(req) => req.result(fresh::data().encrypt(&k, bid)?.as_ref().to_vec()),
        x => panic!("unexpected value: {:?}", x),
    };

    match r.read(res) {
        Err(vault::Error::ProtocolError(_)) => (),
        Err(_) | Ok(_) => panic!("unexpected result"),
    }

    Ok(())
}

#[test]
fn test_storage_returns_stale_blob() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let hint = fresh::record_hint();

    let (bid, blob) = match w.write(&fresh::data(), hint)?.as_slice() {
        [w0, w1] => {
            assert_eq!(w0.kind(), Kind::Transaction);
            assert_eq!(w1.kind(), Kind::Blob);
            (w1.id().to_vec(), w1.data().to_vec())
        }
        ws => panic!("{} unexpected writes", ws.len()),
    };

    match w.write(&fresh::data(), hint)?.as_slice() {
        [w0, w1] => {
            assert_eq!(w0.kind(), Kind::Transaction);
            writes.push(w0.clone());

            assert_eq!(w1.kind(), Kind::Blob);
        }
        ws => panic!("{} unexpected writes", ws.len()),
    };

    let v1 = DBView::load(k.clone(), writes.iter().map(write_to_read))?;

    let r = v1.reader();
    let res = match r.prepare_read(&id)? {
        PreparedRead::CacheMiss(_) => ReadResult::new(Kind::Blob, &bid, &blob),
        x => panic!("unexpected value: {:?}", x),
    };

    match r.read(res) {
        Err(vault::Error::ProtocolError(_)) => (),
        Err(_) | Ok(_) => panic!("unexpected result"),
    }

    Ok(())
}

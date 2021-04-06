mod utils;
use utils::provider::Provider;

use vault::nvault::DbView;
use vault::{Key, RecordHint, RecordId, VaultId};

#[test]
fn test_vaults() {
    let mut view: DbView<Provider> = DbView::new();

    let key0 = Key::random().unwrap();
    let vid0 = VaultId::random::<Provider>().unwrap();
    let rid0 = RecordId::random::<Provider>().unwrap();
    let rid01 = RecordId::random::<Provider>().unwrap();

    let key1 = Key::random().unwrap();
    let vid1 = VaultId::random::<Provider>().unwrap();
    let rid1 = RecordId::random::<Provider>().unwrap();

    // init two vaults.
    view.init_vault(&key0, vid0).unwrap();
    view.init_vault(&key1, vid1).unwrap();
    // write to vault0 and record0
    view.write(&key0, vid0, rid0, b"test0", RecordHint::new(b"hint").unwrap())
        .unwrap();
    // write to vault0 and record01
    view.write(&key0, vid0, rid01, b"test01", RecordHint::new(b"hint").unwrap())
        .unwrap();
    // write to vault1 and record1
    view.write(&key1, vid1, rid1, b"test1", RecordHint::new(b"hint").unwrap())
        .unwrap();

    // read from vault0 and record0
    view.execute_proc(&key0, vid0, rid0, |g| {
        assert_eq!(b"test0", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read from vault0 and record01
    view.execute_proc(&key0, vid0, rid01, |g| {
        assert_eq!(b"test01", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // read from vault1 and record1
    view.execute_proc(&key1, vid1, rid1, |g| {
        assert_eq!(b"test1", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // revoke records rid01 and rid1
    view.revoke_record(&key0, vid0, rid01).unwrap();
    view.revoke_record(&key1, vid1, rid1).unwrap();

    // garbage collect vid0.
    view.garbage_collect_vault(&key0, vid0).unwrap();

    // read vid0 and rid0.
    view.execute_proc(&key0, vid0, rid0, |g| {
        assert_eq!(b"test0", &(*g.borrow()));

        Ok(())
    })
    .unwrap();

    // attempt to use rid01.
    let err = view.execute_proc(&key0, vid0, rid01, |_| Ok(()));
    assert!(err.is_err());

    // attempt to read revoked record rid1.
    let err = view.execute_proc(&key1, vid1, rid1, |_| Ok(()));
    assert!(err.is_err());
}

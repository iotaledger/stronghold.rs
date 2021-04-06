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

    view.init_vault(&key0, vid0).unwrap();
    view.write(&key0, vid0, rid0, b"test", RecordHint::new(b"hint").unwrap())
        .unwrap();

    view.execute_proc(&key0, vid0, rid0, |g| {
        assert_eq!(b"test", &(*g.borrow()));

        Ok(())
    })
    .unwrap();
}

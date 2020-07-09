use vault::{AsView, BoxProvider, DBWriter, DataCommit, Entry, Id, IndexHint, Key, SealedCommit};

use crate::{
    connection::{send_until_success, CRequest},
    line_error,
};

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Client<P: BoxProvider> {
    pub id: Id,
    db: Db<P>,
}

#[derive(Serialize, Deserialize)]
pub struct Db<P: BoxProvider> {
    key: Key<P>,
    db: RefCell<Option<vault::DBView<P>>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    pub fn create_chain(key: Key<P>, id: Id) -> Client<P> {
        let req = DBWriter::<P>::create_chain(&key.clone(), id);
        send_until_success(CRequest::Write(req.clone()));

        let client = Self {
            id: id,
            db: Db::<P>::new(key),
        };

        client
    }

    pub fn create_entry(&self, payload: Vec<u8>) {
        self.db.take(|db| {
            let (_, req) = db
                .writer(self.id)
                .write(&payload, IndexHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            req.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req));
            });
        });
    }

    pub fn list_ids(&self) {
        self.db.take(|db| {
            db.entries()
                .for_each(|(id, hint)| println!("Id: {:?}, Hint: {:?}", id, hint));
        });
    }

    pub fn read_entry_by_id(&self, id: Id) {
        self.db.take(|db| {
            let entries = db.chain.get(&self.id).expect("Couldn't find user id");
            let mut datacommits: Vec<&DataCommit> = Vec::new();

            entries.into_iter().for_each(|ent| {
                if let Some(dc) = ent.typed::<DataCommit>() {
                    datacommits.push(dc);
                }
            });

            let mut finalcommit: Vec<&DataCommit> =
                datacommits.into_iter().filter(|ent| ent.id == id).collect();

            println!("{:?}", finalcommit.pop().expect("No commit with this id"));
        });
    }

    pub fn revoke_entry(&self, id: Id) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).revoke(id).expect(line_error!());

            send_until_success(CRequest::Write(to_write));
            send_until_success(CRequest::Delete(to_delete));
        });
    }

    pub fn perform_gc(&self) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).gc().expect(line_error!());
            to_write.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req.clone()));
            });
            to_delete.into_iter().for_each(|req| {
                send_until_success(CRequest::Delete(req.clone()));
            });
        });
    }
}

impl<P: BoxProvider> Db<P> {
    pub fn new(key: Key<P>) -> Self {
        let req = send_until_success(CRequest::List).list();
        let db = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            db: RefCell::new(Some(db)),
        }
    }

    pub fn take<T>(&self, f: impl FnOnce(vault::DBView<P>) -> T) -> T {
        let mut _db = self.db.borrow_mut();
        let db = _db.take().expect(line_error!());
        let retval = f(db);

        let req = send_until_success(CRequest::List).list();
        *_db = Some(vault::DBView::load(self.key.clone(), req).expect(line_error!()));
        retval
    }
}

// [
//     Entry { sealed: "1v3rWmK2RuIyOoSAuJLK2m4e4GT-PvI4k7XjPACmRLrDrTUwlEww80MAXdkKIJx8KI8-o7lQAUW_WpKtdT-UFYE4WzAWD2ZMdd_cL7XxOzyzwbSqsVdsoYs5WXbeNjW5EYDQiMVuiSOXzxrjARPMurjFVvk2ULasBQxKLVPD2co=", commit: "AAAAAAAAAAotXDaEqpy0hRGc2kSoBQNO7fDSQoAtvy0AAAAAAAAACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", data: None, revocation: None, init: Some(InitCommit { type_id: 10, owner: LVw2hKqctIURnNpEqAUDTu3w0kKALb8t, ctr: 9 }) },
//     Entry { sealed: "nrdPz1qOuvEKsYKDzTv_pkaCsvQkJr-IJcozV_gYSYUPH7mZnONM7KWY31CX6jDjtfzMNmsxDnH6kScWFyvMzkrpjEL8uao51VizskNgA_yhevCmUC2Qw4CUC6E7h79-sYHg4r4b3I-ZwvxIbCJfeGsEKorMgvj0xO1U6DlY3x4=", commit: "AAAAAAAAAAEtXDaEqpy0hRGc2kSoBQNO7fDSQoAtvy0AAAAAAAAACom_2yD7qUobX__5l7f3mvBDaiF0abeRIwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", data: Some(DataCommit { type_id: 1, owner: LVw2hKqctIURnNpEqAUDTu3w0kKALb8t, ctr: 10, id: ib_bIPupShtf__mXt_ea8ENqIXRpt5Ej, index_hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA }), revocation: None, init: None },
//     Entry { sealed: "fiMfpatPqt5-KdNfiKaSOEsibkBDNp88HCn4s5_yQ9SzXS9CCN27Hg7jV9tg7z5DVBHjXwU_9PvRxvJxHiAWE9mAwkrMabjB42q8A8VUIVDomoa57Lm2HVbu5X7aiEGR99lbJ6ZW0ig3l36g-IOkFQAwX-LTtKqL36bt4Mg37OA=", commit: "AAAAAAAAAAEtXDaEqpy0hRGc2kSoBQNO7fDSQoAtvy0AAAAAAAAAC68aQ7GdUCdkDkN81jxQLPJRzM7AFoaimgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", data: Some(DataCommit { type_id: 1, owner: LVw2hKqctIURnNpEqAUDTu3w0kKALb8t, ctr: 11, id: rxpDsZ1QJ2QOQ3zWPFAs8lHMzsAWhqKa, index_hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA }), revocation: None, init: None }
// ]

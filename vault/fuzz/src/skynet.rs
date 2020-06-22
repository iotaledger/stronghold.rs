use crate::{
    crypt::CRng,
    remote::{self, TransactionRequest},
};
use vault::{BoxProvider, DBView, Id, Key};

pub struct Machine<P: BoxProvider> {
    key: Key<P>,
    id: Id,
}

impl<P: BoxProvider> Machine<P> {
    pub fn new(id: Id, key: Key<P>) -> Self {
        Self { key, id }
    }

    pub fn assimilate_rand(&self, others: &[Id]) {
        let other = others[CRng::usize(others.len())];
        let ids = remote::send_until_success(TransactionRequest::List).list();
        let db = DBView::load(self.key.clone(), vault::ListResult::new(ids.into()))
            .expect(line_error!());

        let (to_write, to_delete) = db
            .writer(self.id)
            .take_ownership(&other)
            .expect(line_error!());
        to_write.into_iter().for_each(|req| {
            remote::send_until_success(TransactionRequest::Write(req.clone()));
        });
        to_delete.into_iter().for_each(|req| {
            remote::send_until_success(TransactionRequest::Delete(req.clone()));
        });
    }
}

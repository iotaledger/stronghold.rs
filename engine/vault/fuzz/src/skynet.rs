// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{
    connection::{self, TransactionRequest},
    crypt::CRng,
};
use vault::{BoxProvider, DBView, Id, Key};

// a machine that assimilates other chains.
pub struct Machine<P: BoxProvider> {
    key: Key<P>,
    id: Id,
}

impl<P: BoxProvider> Machine<P> {
    // creates new machine
    pub fn new(id: Id, key: Key<P>) -> Self {
        Self { key, id }
    }

    // Assimilates a chain owned by another.
    pub fn assimilate_rand(&self, others: &[Id]) {
        // pick a random chain and load it.
        let other = others[CRng::usize(others.len())];
        let ids = connection::send_until_success(TransactionRequest::List).list();
        let db = DBView::load(self.key.clone(), vault::ListResult::new(ids.into()))
            .expect(line_error!());

        // take ownership of the foriegn chain
        let (to_write, to_delete) = db
            .writer(self.id)
            .take_ownership(&other)
            .expect(line_error!());
        to_write.into_iter().for_each(|req| {
            connection::send_until_success(TransactionRequest::Write(req.clone()));
        });
        to_delete.into_iter().for_each(|req| {
            connection::send_until_success(TransactionRequest::Delete(req.clone()));
        });
    }
}

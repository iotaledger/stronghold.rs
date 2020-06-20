use crate::{
    crypt_box::{BoxProvider, Key},
    types::{
        commits::{DataCommit, InitCommit, RevocationCommit},
        utils::{Id, IndexHint, Val},
    },
    vault::{
        entries::Entry,
        indices::{ChainIndex, ValidIndex},
    },
};

use std::collections::HashMap;

mod entries;
mod indices;

pub use crate::vault::entries::{DeleteRequest, ListResult, ReadRequest, ReadResult, WriteRequest};

pub struct DBView<P: BoxProvider> {
    key: Key<P>,
    chain: ChainIndex,
    valid: ValidIndex,
}

pub struct DBReader<'a, P: BoxProvider> {
    view: &'a DBView<P>,
}

pub struct DBWriter<P: BoxProvider> {
    view: DBView<P>,
    owner: Id,
}

impl<P: BoxProvider> DBView<P> {
    pub fn load(key: Key<P>, ids: ListResult) -> crate::Result<Self> {
        let entries = ids.into_iter().filter_map(|id| Entry::open(&key, &id));

        let chain = ChainIndex::new(entries)?;
        let valid = ValidIndex::new(&chain);
        Ok(Self { key, chain, valid })
    }

    pub fn entries<'a>(&'a self) -> impl Iterator<Item = (Id, IndexHint)> + ExactSizeIterator + 'a {
        self.valid
            .all()
            .map(|e| e.force_typed::<DataCommit>())
            .map(|d| (d.uid, d.index_hint))
    }

    pub fn absolute_balance(&self) -> (usize, usize) {
        (self.valid.all().count(), self.chain.all().count())
    }

    pub fn chain_ctrs(&self) -> HashMap<Id, u64> {
        self.chain
            .owners()
            .map(|(owner, _)| (*owner, self.chain.force_last(owner).ctr().u64()))
            .collect()
    }

    pub fn not_older_than(&self, chain_ctrs: &HashMap<Id, u64>) -> crate::Result<()> {
        let this_ctrs = self.chain_ctrs();
        chain_ctrs.iter().try_for_each(|(chain, other_ctr)| {
            let this_ctr = this_ctrs
                .get(chain)
                .ok_or(crate::Error::VersionError(String::from(
                    "This database is older than the reference database",
                )))?;
            match this_ctr >= other_ctr {
                true => Ok(()),
                false => Err(crate::Error::VersionError(String::from(
                    "This database is older than the reference database",
                )))?,
            }
        })
    }

    pub fn reader(&self) -> DBReader<P> {
        DBReader { view: self }
    }
    pub fn writer(self, owned_chain: Id) -> DBWriter<P> {
        DBWriter {
            view: self,
            owner: owned_chain,
        }
    }
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    pub fn prepare_read(&self, uid: Id) -> crate::Result<ReadRequest> {
        match self.view.valid.get(&uid) {
            Some(_) => Ok(ReadRequest::payload::<P>(uid)),
            _ => Err(crate::Error::InterfaceError),
        }
    }

    pub fn read(&self, ta: ReadResult) -> crate::Result<Vec<u8>> {
        let uid = Id::load(ta.id()).map_err(|_| crate::Error::InterfaceError)?;
        match self.view.valid.get(&uid) {
            Some(e) => e.open_payload(&self.view.key, ta.data()),
            _ => Err(crate::Error::InterfaceError)?,
        }
    }
}

impl<P: BoxProvider> DBWriter<P> {
    pub fn create_chain(key: &Key<P>, owner: Id) -> WriteRequest {
        let commit = InitCommit::new(owner, Val::from(0u64));
        Entry::new(key, commit).write()
    }

    pub fn relative_balance(&self) -> (usize, usize) {
        let valid = self.view.valid.all_for_owner(&self.owner).count();
        let all = self.view.chain.force_get(&self.owner).len();
        (valid, all)
    }

    pub fn write(self, data: &[u8], hint: IndexHint) -> crate::Result<(Id, Vec<WriteRequest>)> {
        let uid = Id::random::<P>()?;
        let ctr = self.view.chain.force_last(&self.owner).ctr() + 1;

        let commit = DataCommit::new(self.owner, ctr, uid, hint);
        let entry = Entry::new(&self.view.key, commit);
        Ok((uid, entry.write_payload(&self.view.key, data)?))
    }

    pub fn revoke(self, uid: Id) -> crate::Result<(WriteRequest, DeleteRequest)> {
        let start_ctr = match self.view.valid.get(&uid) {
            Some(_) => self.view.chain.force_last(&self.owner).ctr() + 1,
            _ => Err(crate::Error::InterfaceError)?,
        };

        let commit = RevocationCommit::new(self.owner, start_ctr, uid);
        let to_write = Entry::new(&self.view.key, commit).write();
        let to_delete = DeleteRequest::uid(uid);
        Ok((to_write, to_delete))
    }

    pub fn gc(self) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        let start_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
        let start = InitCommit::new(self.owner, start_ctr);
        let mut to_write = vec![Entry::new(&self.view.key, start).write()];

        let revoked: HashMap<_, _> = self.view.chain.own_revoked(&self.owner).collect();
        for data in self.view.chain.foreign_data(&self.owner) {
            if let Some(entry) = revoked.get(&data.force_uid()) {
                let mut commit = entry.commit().clone();
                let view = commit.force_typed_mut::<RevocationCommit>();

                view.ctr = start_ctr + to_write.len() as u64;
                to_write.push(Entry::new(&self.view.key, commit).write())
            }
        }

        for entry in self.view.valid.all_for_owner(&self.owner) {
            let mut commit = entry.commit().clone();
            let view = commit.force_typed_mut::<DataCommit>();
            view.ctr = start_ctr + to_write.len() as u64;

            to_write.push(Entry::new(&self.view.key, commit).write());
        }
        to_write.rotate_left(1);

        let mut to_delete = Vec::new();
        for entry in self.view.chain.force_get(&self.owner) {
            to_delete.push(DeleteRequest::commit(entry.sealed()));
        }
        Ok((to_write, to_delete))
    }
    pub fn take_ownership(
        self,
        other: &Id,
    ) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        let this_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
        let other_ctr = self
            .view
            .chain
            .get(other)
            .map(|_| self.view.chain.force_last(other).ctr() + 1)
            .ok_or(crate::Error::InterfaceError)?;
        let mut to_write = Vec::new();

        let revoked: HashMap<_, _> = self.view.chain.own_revoked(other).collect();
        for data in self.view.chain.foreign_data(other) {
            if let Some(entry) = revoked.get(&data.force_uid()) {
                let this_ctr = this_ctr + to_write.len() as u64;
                let commit = RevocationCommit::new(self.owner, this_ctr, entry.force_uid());
                to_write.push(Entry::new(&self.view.key, commit).write())
            }
        }

        for entry in self.view.valid.all_for_owner(other) {
            let this_ctr = this_ctr + to_write.len() as u64;
            let entry = entry.force_typed::<DataCommit>();
            let commit = DataCommit::new(self.owner, this_ctr, entry.uid, entry.index_hint);
            to_write.push(Entry::new(&self.view.key, commit).write());
        }

        let other_start_commit = InitCommit::new(*other, other_ctr);
        to_write.push(Entry::new(&self.view.key, other_start_commit).write());

        let mut to_delete = Vec::new();
        for entry in self.view.chain.force_get(other) {
            to_delete.push(DeleteRequest::commit(entry.sealed()));
        }
        Ok((to_write, to_delete))
    }
}

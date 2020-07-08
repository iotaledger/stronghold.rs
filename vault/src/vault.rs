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

use serde::{Deserialize, Serialize};

mod entries;
mod indices;

pub use crate::vault::entries::{DeleteRequest, ListResult, ReadRequest, ReadResult, WriteRequest};

// A view over the vault
#[derive(Serialize, Deserialize)]
pub struct DBView<P: BoxProvider> {
    key: Key<P>,
    chain: ChainIndex,
    valid: ValidIndex,
}

// A reader for the DBView
pub struct DBReader<'a, P: BoxProvider> {
    view: &'a DBView<P>,
}

// A writer for the DBView
pub struct DBWriter<P: BoxProvider> {
    view: DBView<P>,
    owner: Id,
}

impl<P: BoxProvider> DBView<P> {
    // opens a vault with a key
    pub fn load(key: Key<P>, ids: ListResult) -> crate::Result<Self> {
        // get entries based on the Ids
        let entries = ids.into_iter().filter_map(|id| Entry::open(&key, &id));

        // build indices
        let chain = ChainIndex::new(entries)?;
        let valid = ValidIndex::new(&chain);

        Ok(Self { key, chain, valid })
    }

    // iterate over all valid ids and index hints
    pub fn entries<'a>(&'a self) -> impl Iterator<Item = (Id, IndexHint)> + ExactSizeIterator + 'a {
        self.valid
            .all()
            .map(|e| e.force_typed::<DataCommit>())
            .map(|d| (d.id, d.index_hint))
    }

    // valid entires compared to total entries
    pub fn absolute_balance(&self) -> (usize, usize) {
        (self.valid.all().count(), self.chain.all().count())
    }

    // get highest counter from the chains
    pub fn chain_ctrs(&self) -> HashMap<Id, u64> {
        self.chain
            .owners()
            .map(|(owner, _)| (*owner, self.chain.force_last(owner).ctr().u64()))
            .collect()
    }

    // check the age of the chains vs the longest chain
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

    // create a reader out of the DBView
    pub fn reader(&self) -> DBReader<P> {
        DBReader { view: self }
    }

    // create a writer out of the DBView
    pub fn writer(self, owned_chain: Id) -> DBWriter<P> {
        DBWriter {
            view: self,
            owner: owned_chain,
        }
    }
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    // create a read transaction to read the entry with inputted id. Returns None if there was no entry for the ID
    pub fn prepare_read(&self, id: Id) -> crate::Result<ReadRequest> {
        match self.view.valid.get(&id) {
            Some(_) => Ok(ReadRequest::payload::<P>(id)),
            _ => Err(crate::Error::InterfaceError),
        }
    }

    // Open the entry
    pub fn read(&self, ta: ReadResult) -> crate::Result<Vec<u8>> {
        // reverse lookup
        let id = Id::load(ta.id()).map_err(|_| crate::Error::InterfaceError)?;
        match self.view.valid.get(&id) {
            Some(e) => e.open_payload(&self.view.key, ta.data()),
            _ => Err(crate::Error::InterfaceError)?,
        }
    }
}

impl<P: BoxProvider> DBWriter<P> {
    // create a new chain owned by owner
    pub fn create_chain(key: &Key<P>, owner: Id) -> WriteRequest {
        let commit = InitCommit::new(owner, Val::from(0u64));
        Entry::new(key, commit).write()
    }

    // amount of valid entries compared to amount of total entries in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        let valid = self.view.valid.all_for_owner(&self.owner).count();
        let all = self.view.chain.force_get(&self.owner).len();
        (valid, all)
    }

    // generate a commit and return the entry's id along with a WriteRequest.
    pub fn write(self, data: &[u8], hint: IndexHint) -> crate::Result<(Id, Vec<WriteRequest>)> {
        // generate id
        let id = Id::random::<P>()?;
        // get counter
        let ctr = self.view.chain.force_last(&self.owner).ctr() + 1;

        // create commit
        let commit = DataCommit::new(self.owner, ctr, id, hint);
        // create entry
        let entry = Entry::new(&self.view.key, commit);
        Ok((id, entry.write_payload(&self.view.key, data)?))
    }

    // creates a revocation commit.  Returns WriteRequest and DeleteRequest
    pub fn revoke(self, id: Id) -> crate::Result<(WriteRequest, DeleteRequest)> {
        // check if id is still valid and get counter
        let start_ctr = match self.view.valid.get(&id) {
            Some(_) => self.view.chain.force_last(&self.owner).ctr() + 1,
            _ => Err(crate::Error::InterfaceError)?,
        };

        // generate commit
        let commit = RevocationCommit::new(self.owner, start_ctr, id);
        // generate entry
        let to_write = Entry::new(&self.view.key, commit).write();
        // create delete request
        let to_delete = DeleteRequest::uid(id);
        Ok((to_write, to_delete))
    }

    // create a new InitCommit for an owned chain.  Returns WriteRequests and DeleteRequests
    pub fn gc(self) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // create InitCommit
        let start_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
        let start = InitCommit::new(self.owner, start_ctr);
        let mut to_write = vec![Entry::new(&self.view.key, start).write()];

        // Recommit revocation commit
        let revoked: HashMap<_, _> = self.view.chain.own_revoked(&self.owner).collect();
        for data in self.view.chain.foreign_data(&self.owner) {
            if let Some(entry) = revoked.get(&data.force_uid()) {
                // clone and get view of commit
                let mut commit = entry.commit().clone();
                let view = commit.force_typed_mut::<RevocationCommit>();

                // update commit and create transaction
                view.ctr = start_ctr + to_write.len() as u64;
                to_write.push(Entry::new(&self.view.key, commit).write())
            }
        }

        // recommit data
        for entry in self.view.valid.all_for_owner(&self.owner) {
            // create updated commit
            let mut commit = entry.commit().clone();
            let view = commit.force_typed_mut::<DataCommit>();
            view.ctr = start_ctr + to_write.len() as u64;

            // create the transaction
            to_write.push(Entry::new(&self.view.key, commit).write());
        }
        // move init commit to end.  Keeps the old chain valid until the new InitCommit is written.
        to_write.rotate_left(1);

        // create a delete transction to delete all old and non-valid commits
        let mut to_delete = Vec::new();
        for entry in self.view.chain.force_get(&self.owner) {
            to_delete.push(DeleteRequest::commit(entry.sealed()));
        }
        Ok((to_write, to_delete))
    }

    // take ownership of a chain
    pub fn take_ownership(
        self,
        other: &Id,
    ) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // get counters
        let this_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
        let other_ctr = self
            .view
            .chain
            .get(other)
            .map(|_| self.view.chain.force_last(other).ctr() + 1)
            .ok_or(crate::Error::InterfaceError)?;
        let mut to_write = Vec::new();

        // Recommit Revocation commit
        let revoked: HashMap<_, _> = self.view.chain.own_revoked(other).collect();
        for data in self.view.chain.foreign_data(other) {
            if let Some(entry) = revoked.get(&data.force_uid()) {
                let this_ctr = this_ctr + to_write.len() as u64;
                let commit = RevocationCommit::new(self.owner, this_ctr, entry.force_uid());
                to_write.push(Entry::new(&self.view.key, commit).write())
            }
        }

        // copy all valid commits
        for entry in self.view.valid.all_for_owner(other) {
            let this_ctr = this_ctr + to_write.len() as u64;
            let entry = entry.force_typed::<DataCommit>();
            let commit = DataCommit::new(self.owner, this_ctr, entry.id, entry.index_hint);
            to_write.push(Entry::new(&self.view.key, commit).write());
        }

        // create an InitCommit
        let other_start_commit = InitCommit::new(*other, other_ctr);
        to_write.push(Entry::new(&self.view.key, other_start_commit).write());

        // delete the old commits
        let mut to_delete = Vec::new();
        for entry in self.view.chain.force_get(other) {
            to_delete.push(DeleteRequest::commit(entry.sealed()));
        }
        Ok((to_write, to_delete))
    }
}

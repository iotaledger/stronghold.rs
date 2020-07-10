use crate::{
    base64::Base64Encodable,
    crypt_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        commits::{
            Commit, DataCommit, InitCommit, RevocationCommit, SealedCommit, SealedPayload,
            TypedCommit,
        },
        utils::{Id, Val},
        AsView,
    },
};

use std::{
    fmt::{self, Debug, Formatter},
    vec::IntoIter,
};

use serde::{Deserialize, Serialize};

// result of a list transaction
#[derive(Clone)]
pub struct ListResult {
    ids: Vec<Vec<u8>>,
}

// a read transaction
#[derive(Clone)]
pub struct ReadRequest {
    id: Vec<u8>,
}

// a read transaction result
#[derive(Clone)]
pub struct ReadResult {
    id: Vec<u8>,
    data: Vec<u8>,
}

// a write transaction
#[derive(Clone)]
pub struct WriteRequest {
    id: Vec<u8>,
    data: Vec<u8>,
}

// a delete transaction
#[derive(Clone)]
pub struct DeleteRequest {
    id: Vec<u8>,
}

// an entry in the vault
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry((Commit, SealedCommit));

impl ListResult {
    // create new list result
    pub fn new(ids: Vec<Vec<u8>>) -> Self {
        Self { ids }
    }
    // get the ids of entries
    pub fn ids(&self) -> &Vec<Vec<u8>> {
        &self.ids
    }
}

impl ReadRequest {
    // create a new read request
    pub fn payload<P: BoxProvider>(id: Id) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }
    // id of entry
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl ReadResult {
    // new read result
    pub fn new(id: Vec<u8>, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    // id of read result
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    // data of entry
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl WriteRequest {
    // create a new write request
    pub(in crate) fn commit(commit: &SealedCommit) -> Self {
        Self {
            id: commit.as_ref().to_vec(),
            data: Vec::new(),
        }
    }

    // creates a new request to write
    pub(in crate) fn payload(id: Id, payload: SealedPayload) -> Self {
        Self {
            id: id.as_ref().to_vec(),
            data: payload.as_ref().to_vec(),
        }
    }

    // id of entry
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    // data of entry
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl DeleteRequest {
    // create new delete request
    pub(in crate) fn commit(commit: &SealedCommit) -> Self {
        Self {
            id: commit.as_ref().to_vec(),
        }
    }

    // create delete request by id
    pub(in crate) fn uid(id: Id) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }

    // get id of delete request
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl Entry {
    // open a commit from entry by id
    pub fn open<P: BoxProvider>(key: &Key<P>, id: &[u8]) -> Option<Self> {
        // get fields and create commit
        let sealed = SealedCommit::from(id.to_vec());
        let packed = sealed.decrypt(key, b"").ok()?;
        Some(Self((packed, sealed)))
    }
    // create a new entry
    pub fn new<P: BoxProvider>(key: &Key<P>, commit: Commit) -> Self {
        let sealed = commit.encrypt(key, b"").expect("Failed to encrypt commit");
        Self((commit, sealed))
    }

    // create a sealed commit
    pub fn sealed(&self) -> &SealedCommit {
        &(self.0).1
    }

    // the commit for this entry
    pub fn commit(&self) -> &Commit {
        &(self.0).0
    }

    // get a typed commit view
    pub fn typed<T: TypedCommit>(&self) -> Option<&T>
    where
        Commit: AsView<T>,
    {
        self.commit().typed()
    }

    // get a typed commit view
    pub fn force_typed<T: TypedCommit>(&self) -> &T
    where
        Commit: AsView<T>,
    {
        self.commit().force_typed()
    }

    // get commit owner
    pub fn owner(&self) -> Id {
        self.commit().untyped().owner
    }

    // get commit counter
    pub fn ctr(&self) -> Val {
        self.commit().untyped().ctr
    }

    // the id if the entry is data or a revoke
    pub fn force_uid(&self) -> Id {
        self.typed::<DataCommit>()
            .map(|d| d.id)
            .or_else(|| self.typed::<RevocationCommit>().map(|r| r.id))
            .expect("There is no Id in this commit")
    }

    // create a write request
    pub fn write(&self) -> WriteRequest {
        WriteRequest::commit(self.sealed())
    }

    // create a write request
    pub fn write_payload<P: BoxProvider>(
        &self,
        key: &Key<P>,
        data: &[u8],
    ) -> crate::Result<Vec<WriteRequest>> {
        let id = self.force_typed::<DataCommit>().id;
        let payload: SealedPayload = data
            .to_vec()
            .encrypt(key, id.as_ref())
            .expect("Failed to encrypt payload");
        Ok(vec![
            WriteRequest::payload(id, payload),
            WriteRequest::commit(self.sealed()),
        ])
    }

    // open the payload
    pub fn open_payload<P: BoxProvider>(
        &self,
        key: &Key<P>,
        data: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let id = self.force_typed::<DataCommit>().id;
        let payload = SealedPayload::from(data.to_vec()).decrypt(key, id.as_ref())?;
        Ok(payload)
    }
}

impl Into<Vec<Vec<u8>>> for ListResult {
    fn into(self) -> Vec<Vec<u8>> {
        self.ids
    }
}

impl IntoIterator for ListResult {
    type Item = Vec<u8>;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.into_iter()
    }
}

impl Into<Vec<u8>> for ReadRequest {
    fn into(self) -> Vec<u8> {
        self.id
    }
}

impl Into<(Vec<u8>, Vec<u8>)> for ReadResult {
    fn into(self) -> (Vec<u8>, Vec<u8>) {
        (self.id, self.data)
    }
}

impl Into<(Vec<u8>, Vec<u8>)> for WriteRequest {
    fn into(self) -> (Vec<u8>, Vec<u8>) {
        (self.id, self.data)
    }
}

impl Into<Vec<u8>> for DeleteRequest {
    fn into(self) -> Vec<u8> {
        self.id
    }
}

// debug for entry
impl Debug for Entry {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Entry")
            .field("sealed", &self.sealed().base64())
            .field("commit", &self.commit().base64())
            .field("data", &self.typed::<DataCommit>())
            .field("revocation", &self.typed::<RevocationCommit>())
            .field("init", &self.typed::<InitCommit>())
            .finish()
    }
}

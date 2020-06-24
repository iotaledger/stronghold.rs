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
    sync::Arc,
    vec::IntoIter,
};

#[derive(Clone)]
pub struct ListResult {
    ids: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct ReadRequest {
    id: Vec<u8>,
}

#[derive(Clone)]
pub struct ReadResult {
    id: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Clone)]
pub struct WriteRequest {
    id: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Clone)]
pub struct DeleteRequest {
    id: Vec<u8>,
}

#[derive(Clone)]
pub struct Entry(Arc<(Commit, SealedCommit)>);

impl ListResult {
    pub fn new(ids: Vec<Vec<u8>>) -> Self {
        Self { ids }
    }
    pub fn ids(&self) -> &Vec<Vec<u8>> {
        &self.ids
    }
}

impl ReadRequest {
    pub(in crate) fn payload<P: BoxProvider>(id: Id) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl ReadResult {
    pub fn new(id: Vec<u8>, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl WriteRequest {
    pub(in crate) fn commit(commit: &SealedCommit) -> Self {
        Self {
            id: commit.as_ref().to_vec(),
            data: Vec::new(),
        }
    }

    pub(in crate) fn payload(id: Id, payload: SealedPayload) -> Self {
        Self {
            id: id.as_ref().to_vec(),
            data: payload.as_ref().to_vec(),
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl DeleteRequest {
    pub(in crate) fn commit(commit: &SealedCommit) -> Self {
        Self {
            id: commit.as_ref().to_vec(),
        }
    }

    pub(in crate) fn uid(id: Id) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl Entry {
    pub fn open<P: BoxProvider>(key: &Key<P>, id: &[u8]) -> Option<Self> {
        let sealed = SealedCommit::from(id.to_vec());
        let packed = sealed.decrypt(key, b"").ok()?;
        Some(Self(Arc::new((packed, sealed))))
    }
    pub fn new<P: BoxProvider>(key: &Key<P>, commit: Commit) -> Self {
        let sealed = commit.encrypt(key, b"").expect("Failed to encrypt commit");
        Self(Arc::new((commit, sealed)))
    }

    pub fn sealed(&self) -> &SealedCommit {
        &(self.0).1
    }

    pub fn commit(&self) -> &Commit {
        &(self.0).0
    }

    pub fn typed<T: TypedCommit>(&self) -> Option<&T>
    where
        Commit: AsView<T>,
    {
        self.commit().typed()
    }

    pub fn force_typed<T: TypedCommit>(&self) -> &T
    where
        Commit: AsView<T>,
    {
        self.commit().force_typed()
    }

    pub fn owner(&self) -> Id {
        self.commit().untyped().owner
    }

    pub fn ctr(&self) -> Val {
        self.commit().untyped().ctr
    }

    pub fn force_uid(&self) -> Id {
        self.typed::<DataCommit>()
            .map(|d| d.id)
            .or_else(|| self.typed::<RevocationCommit>().map(|r| r.id))
            .expect("There is no Id in this commit")
    }

    pub fn write(&self) -> WriteRequest {
        WriteRequest::commit(self.sealed())
    }

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

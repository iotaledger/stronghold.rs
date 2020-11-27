use riker::actors::*;

use engine::vault::{RecordHint, RecordId};

use std::path::PathBuf;

use crate::{ids::VaultId, line_error};

use std::collections::HashMap;

pub struct ExternalCacheActor {
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    // Contains the VaultIds in order of creation.
    index: Vec<VaultId>,
}

/// Messages to interact with Stronghold
#[derive(Clone, Debug)]
pub enum StrongholdMessage {
    CreateNewVault,
    CreateVaultReturn(VaultId, RecordId),
    WriteData(usize, Vec<u8>, RecordHint),
    InitRecord(usize),
    ReturnInitRecord(VaultId, RecordId),
    ReturnReadData(Vec<u8>),
    ReadData(usize),
    RevokeData(usize),
    GarbageCollect(usize),
    ListIds(usize),
    ReturnList(Vec<(RecordId, RecordHint)>),
    WriteSnapshot(String, Option<PathBuf>),
    ReadSnapshot(String, Option<PathBuf>),
}

impl ExternalCacheActor {
    pub fn new() -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();
        let index = Vec::new();

        Self { vaults, heads, index }
    }

    pub fn add_vault(&mut self, vid: VaultId, rid: RecordId) {
        self.heads.push(rid);

        self.index.push(vid);

        let idx = self.index.len() - 1;

        self.vaults.insert(vid, (idx, vec![rid]));
    }

    pub fn insert_record(&mut self, vid: VaultId, rid: RecordId) {
        let mut heads: Vec<RecordId> = self.heads.clone();
        let mut index: Vec<VaultId> = self.index.clone();

        let (idx, rids) = self
            .vaults
            .entry(vid)
            .and_modify(|(idx, rids)| {
                rids.push(rid);

                if heads.len() <= *idx {
                    heads.push(rid);
                } else {
                    heads[*idx] = rid;
                }
            })
            .or_insert((0, vec![rid]));

        if !heads.contains(&rid) {
            heads.push(rid);
        }

        if !index.contains(&vid) {
            index.push(vid);
        }

        self.index = index;
        self.heads = heads;
    }

    pub fn get_head(&self, index: usize) -> Option<RecordId> {
        if self.heads.len() <= index {
            None
        } else {
            Some(self.heads[index])
        }
    }

    pub fn get_vault(&self, index: usize) -> Option<VaultId> {
        if self.index.len() <= index {
            None
        } else {
            Some(self.index[index])
        }
    }

    pub fn get_index(&self, vid: VaultId) -> Option<usize> {
        if self.vaults.contains_key(&vid) {
            let (idx, _) = self.vaults.get(&vid).expect(line_error!());

            Some(*idx)
        } else {
            None
        }
    }
}

impl Actor for ExternalCacheActor {
    type Msg = StrongholdMessage;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl ActorFactory for ExternalCacheActor {
    fn create() -> Self {
        ExternalCacheActor::new()
    }
}

impl Receive<StrongholdMessage> for ExternalCacheActor {
    type Msg = StrongholdMessage;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            StrongholdMessage::CreateNewVault => {}
            StrongholdMessage::CreateVaultReturn(vid, rid) => {}
            StrongholdMessage::WriteData(index, payload, hint) => {}
            StrongholdMessage::InitRecord(index) => {}
            StrongholdMessage::ReturnInitRecord(vid, rid) => {}
            StrongholdMessage::ReturnReadData(payload) => {}
            StrongholdMessage::ReadData(index) => {}
            StrongholdMessage::RevokeData(index) => {}
            StrongholdMessage::GarbageCollect(index) => {}
            StrongholdMessage::ListIds(index) => {}
            StrongholdMessage::ReturnList(records_and_hints) => {}
            StrongholdMessage::WriteSnapshot(pass, path) => {}
            StrongholdMessage::ReadSnapshot(pass, path) => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::provider::Provider;

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut external = ExternalCacheActor::new();

        external.add_vault(vid, rid);

        assert_eq!(external.index.len(), 1);
        assert_eq!(external.heads.len(), 1);
        assert_eq!(external.index[0], vid);
        assert_eq!(external.heads[0], rid);
        assert_eq!(external.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        external.add_vault(vid, rid);

        assert_eq!(external.index.len(), 2);
        assert_eq!(external.heads.len(), 2);
        assert_eq!(external.index[1], vid);
        assert_eq!(external.heads[1], rid);
        assert_eq!(external.vaults.get(&vid), Some(&(1usize, vec![rid])));
    }

    #[test]
    fn test_insert() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut external = ExternalCacheActor::new();

        external.insert_record(vid, rid);

        assert_eq!(external.index.len(), 1);
        assert_eq!(external.heads.len(), 1);
        assert_eq!(external.index[0], vid);
        assert_eq!(external.heads[0], rid);
        assert_eq!(external.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        external.insert_record(vid, rid2);

        assert_eq!(external.index.len(), 1);
        assert_eq!(external.heads.len(), 1);
        assert_eq!(external.heads[0], rid2);
        assert_eq!(external.index[0], vid);
        assert_eq!(external.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        external.add_vault(vid2, rid3);
        external.insert_record(vid2, rid4);

        assert_eq!(external.index.len(), 2);
        assert_eq!(external.heads.len(), 2);
        assert_eq!(external.heads[1], rid4);
        assert_eq!(external.index[1], vid2);
        assert_eq!(external.vaults.get(&vid2), Some(&(1usize, vec![rid3, rid4])));
    }

    #[test]
    fn test_get_head_and_vault() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let mut external = ExternalCacheActor::new();

        external.add_vault(vid, rid);
        external.insert_record(vid, rid2);
        external.add_vault(vid2, rid3);
        external.insert_record(vid2, rid4);

        let head0 = external.get_head(0);
        let head1 = external.get_head(1);
        let head2 = external.get_head(2);

        assert_eq!(head0, Some(rid2));
        assert_eq!(head1, Some(rid4));
        assert_eq!(head2, None);

        let vault0 = external.get_vault(0);
        let vault1 = external.get_vault(1);
        let vault2 = external.get_vault(3);

        assert_eq!(vault0, Some(vid));
        assert_eq!(vault1, Some(vid2));
        assert_eq!(vault2, None);
    }
}

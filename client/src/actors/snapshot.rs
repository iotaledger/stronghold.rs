// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use actix::{Actor, Handler, Message, MessageResult, Supervised};

use std::path::PathBuf;

use engine::{
    snapshot,
    vault::{BlobId, ClientId, DbView, Key, RecordId, VaultId},
};

use crate::{
    internals,
    state::{
        secure::Store,
        snapshot::{ReadError, Snapshot, SnapshotState, WriteError},
    },
    Provider,
};
use std::collections::HashMap;

/// re-export local modules
pub use messages::*;
pub use returntypes::*;

pub mod returntypes {

    use super::*;

    /// Return type for loaded snapshot file
    pub struct ReturnReadSnapshot {
        pub id: ClientId,

        pub data: Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>,
    }
}

pub mod messages {

    use serde::{Deserialize, Serialize};

    use crate::sync::{MergeClientsMapper, MergeSnapshotsMapper, SelectOne, SelectOrMerge};

    use super::*;

    pub struct WriteSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
    }

    impl Message for WriteSnapshot {
        type Result = Result<(), WriteError>;
    }

    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = ();
    }

    pub struct ReadFromSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub id: ClientId,
        pub fid: Option<ClientId>,
    }

    impl Message for ReadFromSnapshot {
        type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct MergeClients {
        pub source: ClientId,
        pub target: ClientId,
        pub mapper: Option<MergeClientsMapper>,
        pub merge_policy: SelectOrMerge<SelectOne>,
    }

    #[derive(Message, Debug, Clone, Serialize, Deserialize)]
    #[rtype(result = "HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>>")]
    pub struct GetHierarchy;

    #[derive(Message, Debug, Clone)]
    #[rtype(result = "HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>>")]
    pub struct GetDiff {
        pub other: HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>>,
        pub mapper: Option<MergeSnapshotsMapper>,
        pub merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    }

    #[derive(Message, Debug, Clone, Serialize, Deserialize)]
    #[rtype(result = "Vec<u8>")]
    pub struct ExportDiff {
        pub key: snapshot::Key,
        pub diff: HashMap<ClientId, HashMap<VaultId, Vec<(RecordId, BlobId)>>>,
    }

    #[derive(Message, Debug, Clone)]
    #[rtype(result = "()")]
    pub struct ImportSnapshot {
        pub key: snapshot::Key,
        pub blob: Vec<u8>,
        pub mapper: Option<MergeSnapshotsMapper>,
        pub merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    }
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

// actix impl
impl Supervised for Snapshot {}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::FillSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.state.add_data(msg.id, *msg.data);
    }
}

impl Handler<messages::ReadFromSnapshot> for Snapshot {
    type Result = Result<returntypes::ReturnReadSnapshot, ReadError>;

    /// This will try to read from a snapshot on disk, otherwise load from a local snapshot
    /// in memory. Returns the loaded snapshot data, that must be loaded inside the client
    /// for access.
    fn handle(&mut self, msg: messages::ReadFromSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        let id = msg.fid.unwrap_or(msg.id);

        if self.has_data(id) {
            let data = self.get_state(id);

            Ok(ReturnReadSnapshot {
                id,
                data: Box::new(data),
            })
        } else {
            let mut snapshot = Snapshot::read_from_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;
            let data = snapshot.get_state(id);
            *self = snapshot;

            Ok(ReturnReadSnapshot {
                id,
                data: Box::new(data),
            })
        }
    }
}

impl Handler<messages::WriteSnapshot> for Snapshot {
    type Result = Result<(), WriteError>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;

        self.state = SnapshotState::default();

        Ok(())
    }
}

impl Handler<messages::MergeClients> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::MergeClients, _ctx: &mut Self::Context) -> Self::Result {
        self.sync_clients(msg.source, msg.target, msg.mapper, msg.merge_policy)
    }
}

impl Handler<messages::GetHierarchy> for Snapshot {
    type Result = MessageResult<messages::GetHierarchy>;

    fn handle(&mut self, _: messages::GetHierarchy, _ctx: &mut Self::Context) -> Self::Result {
        let hierarchy = self.get_hierarchy();
        MessageResult(hierarchy)
    }
}

impl Handler<messages::GetDiff> for Snapshot {
    type Result = MessageResult<messages::GetDiff>;

    fn handle(&mut self, msg: messages::GetDiff, _ctx: &mut Self::Context) -> Self::Result {
        let diff = self.get_diff(msg.other, msg.mapper.as_ref(), &msg.merge_policy);
        MessageResult(diff)
    }
}

impl Handler<messages::ExportDiff> for Snapshot {
    type Result = Vec<u8>;

    fn handle(&mut self, msg: messages::ExportDiff, _ctx: &mut Self::Context) -> Self::Result {
        self.export_to_serialized_state(msg.diff, msg.key)
    }
}

impl Handler<messages::ImportSnapshot> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::ImportSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.import_from_serialized_state(msg.blob, msg.key, msg.mapper.as_ref(), &msg.merge_policy)
    }
}

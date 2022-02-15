// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use crate::{
    internals,
    state::{
        secure::Store,
        snapshot::{MergeError, ReadError, Snapshot, SnapshotState, WriteError},
    },
    sync::{MergeLayer, SnapshotStateHierarchy},
    Provider,
};
use actix::{Actor, Handler, Message, MessageResult, Supervised};
use crypto::keys::x25519;
use engine::{
    snapshot,
    vault::{ClientId, DbView, Key, VaultId},
};
use std::{collections::HashMap, path::PathBuf};

/// re-export local modules
pub use messages::*;
pub use returntypes::*;

use super::VaultError;

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

    use crypto::keys::x25519;
    use serde::{Deserialize, Serialize};

    use crate::sync::{MergeClientsMapper, MergeSnapshotsMapper, SelectOne, SelectOrMerge, SnapshotStateHierarchy};

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

    pub struct LoadFromState {
        pub id: ClientId,
        pub fid: Option<ClientId>,
    }

    impl Message for LoadFromState {
        type Result = Option<returntypes::ReturnReadSnapshot>;
    }

    #[derive(Message)]
    #[rtype(result = "Result<Option<()>, VaultError>")]
    pub struct MergeClients {
        pub source: ClientId,
        pub target: ClientId,
        pub mapper: Option<MergeClientsMapper>,
        pub merge_policy: SelectOrMerge<SelectOne>,
    }

    // Get the public key of the stored x25519 private key.
    #[derive(Message)]
    #[rtype(result = "[u8; x25519::PUBLIC_KEY_LENGTH]")]
    pub struct GetDhPub;

    /// Export local hierarchy.
    #[derive(Message, Debug, Clone, Serialize, Deserialize)]
    #[rtype(result = "Result<SnapshotStateHierarchy, VaultError>")]
    pub struct GetHierarchy;

    /// Calculate diff between local hierarchy and the given one.
    #[derive(Message, Debug, Clone)]
    #[rtype(result = "Result<SnapshotStateHierarchy, VaultError>")]
    pub struct GetDiff {
        pub other: SnapshotStateHierarchy,
        pub mapper: Option<MergeSnapshotsMapper>,
        pub merge_policy: SelectOrMerge<SelectOrMerge<SelectOne>>,
    }

    // Export the given diff from the local vaults.
    // Returns the serialized snapshot and the local public key.
    // The snapshot is encrypted with a shared secret created from the local x25519
    // secret key and the remote's public key.
    #[derive(Message, Debug, Clone, Serialize, Deserialize)]
    #[rtype(result = "Result<(Vec<u8>, [u8; x25519::PUBLIC_KEY_LENGTH]), MergeError>")]
    pub struct ExportDiff {
        // Public key of the remote.
        pub dh_pub_key: [u8; x25519::PUBLIC_KEY_LENGTH],
        pub diff: SnapshotStateHierarchy,
    }

    #[derive(Message, Debug, Clone)]
    #[rtype(result = "Result<(), MergeError>")]
    pub struct ImportSnapshot {
        // Public key of the remote.
        pub dh_pub_key: [u8; x25519::PUBLIC_KEY_LENGTH],
        // Serialized snapshot, encrypted with a diffie-hellmann shared secret created from the key
        // sent in `ExportDiff` and the remote's secret key.
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

impl Handler<messages::LoadFromState> for Snapshot {
    type Result = Option<returntypes::ReturnReadSnapshot>;

    /// This will load from a local snapshot state in memory. Return `None` if there is no client with
    /// this id.
    fn handle(&mut self, msg: messages::LoadFromState, _ctx: &mut Self::Context) -> Self::Result {
        let id = msg.fid.unwrap_or(msg.id);
        if !self.has_data(id) {
            return None;
        }
        let data = self.get_state(id);

        Some(ReturnReadSnapshot {
            id,
            data: Box::new(data),
        })
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
    type Result = Result<Option<()>, VaultError>;

    fn handle(&mut self, msg: messages::MergeClients, _ctx: &mut Self::Context) -> Self::Result {
        self.sync_clients(msg.source, msg.target, msg.mapper, msg.merge_policy)
    }
}

impl Handler<messages::GetDhPub> for Snapshot {
    type Result = MessageResult<messages::GetDhPub>;

    fn handle(&mut self, _: messages::GetDhPub, _ctx: &mut Self::Context) -> Self::Result {
        let key = self.get_dh_pub_key().to_bytes();
        MessageResult(key)
    }
}

impl Handler<messages::GetHierarchy> for Snapshot {
    type Result = Result<SnapshotStateHierarchy, VaultError>;

    fn handle(&mut self, _: messages::GetHierarchy, _ctx: &mut Self::Context) -> Self::Result {
        self.state.get_hierarchy()
    }
}

impl Handler<messages::GetDiff> for Snapshot {
    type Result = Result<SnapshotStateHierarchy, VaultError>;

    fn handle(&mut self, msg: messages::GetDiff, _ctx: &mut Self::Context) -> Self::Result {
        self.state.get_diff(msg.other, msg.mapper.as_ref(), &msg.merge_policy)
    }
}

impl Handler<messages::ExportDiff> for Snapshot {
    type Result = Result<(Vec<u8>, [u8; x25519::PUBLIC_KEY_LENGTH]), MergeError>;

    fn handle(&mut self, msg: messages::ExportDiff, _ctx: &mut Self::Context) -> Self::Result {
        self.export_to_serialized_state(msg.diff, msg.dh_pub_key)
    }
}

impl Handler<messages::ImportSnapshot> for Snapshot {
    type Result = Result<(), MergeError>;

    fn handle(&mut self, msg: messages::ImportSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.import_from_serialized_state(msg.blob, msg.dh_pub_key, msg.mapper.as_ref(), &msg.merge_policy)
    }
}

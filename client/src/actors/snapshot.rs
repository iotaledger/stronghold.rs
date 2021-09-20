// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use actix::{Actor, Handler, Message, Supervised};

use std::path::PathBuf;

use engine::{
    snapshot,
    vault::{ClientId, DbView, Key, VaultId},
};

use crate::{
    internals, line_error,
    state::{
        secure::Store,
        snapshot::{Snapshot, SnapshotState},
    },
    Provider,
};
use std::collections::HashMap;
use thiserror::Error as DeriveError;

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

    use super::*;

    pub struct WriteSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
    }

    impl Message for WriteSnapshot {
        type Result = Result<(), SnapshotError>;
    }

    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Default)]
    pub struct ReadFromSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub id: ClientId,
        pub fid: Option<ClientId>,
    }

    impl Message for ReadFromSnapshot {
        type Result = Result<returntypes::ReturnReadSnapshot, anyhow::Error>;
    }

    /// Message for [`Snapshot`] to create a partially synchronized snapshot.
    /// A partially synchronized snapshot contains only the associated data like
    /// vaults and their records, that is related to specified [`ClientId`]s
    /// and their associated keys.
    pub struct PartialSynchronization {
        // this passes a list of all allowed client_ids
        // to be synchronized
        pub allowed: Vec<ClientId>,

        // this snapshot file will be used as base snapshot
        pub source: SnapshotConfig,

        // this snapshot file will be used to compare against
        // the source snapshot
        pub compare: SnapshotConfig,

        // this is the destination snapshot to written out
        pub destination: SnapshotConfig,

        // the currently used client id
        pub id: ClientId,
    }

    /// Message for [`Snapshot`] to create a fully synchronized snapshot.
    /// A fully synchronized snapshot contains all [`ClientId`]s, and
    /// all associated data like vaults and their records.
    pub struct FullSynchronization {
        // this snapshot file will be used as base snapshot
        pub source: SnapshotConfig,

        // this is the snapshot to synchronized with the current state
        pub merge: SnapshotConfig,

        // this is the destination snapshot to written out
        pub destination: SnapshotConfig,

        // the current [`ClientId`]
        pub id: ClientId,
    }

    impl Message for FullSynchronization {
        type Result = Result<Option<Vec<u8>>, SnapshotError>;
    }

    impl Message for PartialSynchronization {
        type Result = Result<Option<Vec<u8>>, SnapshotError>;
    }
}

/// This struct provide file system configuration to the messages ['FullSynchronization`]
/// and [`PartialSynchronization`] it optionally expects a `path` or a `filename`, either
/// the stronghold snapshot resides at another place than the default, or the latter, if
/// the name of the snapshot is known.
#[derive(Clone)]
pub struct SnapshotConfig {
    // the filename of the snapshot file in the default snapshot directory
    pub filename: Option<String>,

    // the path to the snapshot file, if it is not inside the default folder
    pub path: Option<PathBuf>,

    // the key to encrypt / decrypt the snapshot file
    pub key: snapshot::Key,

    // set this to `true` will generate the written output as slice of bytes
    pub generates_output: bool,
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("Could Not Load Snapshot. Try another password")]
    LoadFailure,

    #[error("Could Not Synchronize Snapshot: ({0})")]
    SynchronizeSnapshot(String),

    #[error("Could Not Deserialize Snapshot: ({0})")]
    DeserializationFailure(String),

    #[error("Could Not Serialize Snapshot: ({0})")]
    SerializationFailure(String),

    #[error("Could Not Write Snapshot to File: ({0})")]
    WriteSnapshotFailure(String),
}

// actix impl
impl Supervised for Snapshot {}

impl Handler<messages::FullSynchronization> for Snapshot {
    type Result = Result<Option<Vec<u8>>, SnapshotError>;

    fn handle(&mut self, msg: messages::FullSynchronization, ctx: &mut Self::Context) -> Self::Result {
        // locally import necessary modules
        use engine::vault::Key as PKey;
        use serde::{Deserialize, Serialize};

        // define local snapshot data structure to access the private fields
        #[derive(Deserialize, Serialize, Default)]
        struct SnapshotStateLocal(pub HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

        let merge_config = msg.merge;
        let snapshot_data_merge = Snapshot::read_from_name_or_path(
            merge_config.filename.as_deref(),
            merge_config.path.as_deref(),
            merge_config.key,
        )
        .map_err(|error| SnapshotError::SerializationFailure(error.to_string()))?;

        let local_config = msg.source;
        let snapshot_data_local = Snapshot::read_from_name_or_path(
            local_config.filename.as_deref(),
            local_config.path.as_deref(),
            local_config.key,
        )
        .map_err(|error| SnapshotError::SerializationFailure(error.to_string()))?;

        let dst_config = msg.destination;

        let snapshot_local = bincode::deserialize::<SnapshotStateLocal>(&snapshot_data_local)
            .map_err(|error| SnapshotError::SynchronizeSnapshot(error.to_string()))?;

        // merge this state into current state
        let snapshot_merge = bincode::deserialize::<SnapshotStateLocal>(&snapshot_data_merge)
            .map_err(|error| SnapshotError::SynchronizeSnapshot(error.to_string()))?;

        let mut output_state = SnapshotState::default();

        // copy all merge
        snapshot_merge.0.keys().for_each(|id| {
            if let Some(data) = snapshot_merge.0.get(id) {
                output_state.add_data(*id, data.clone());
            }
        });

        // copy all local
        snapshot_local.0.keys().for_each(|id| {
            if let Some(data) = snapshot_local.0.get(id) {
                output_state.add_data(*id, data.clone());
            }
        });

        self.state = output_state;

        let write_msg = WriteSnapshot {
            key: dst_config.key,
            filename: dst_config.filename,
            path: dst_config.path,
        };

        // write the new state to disk
        <Self as Handler<WriteSnapshot>>::handle(self, write_msg, ctx)?;

        // return serialized state
        Ok(Some(self.state.serialize()))
    }
}

impl Handler<messages::PartialSynchronization> for Snapshot {
    type Result = Result<Option<Vec<u8>>, SnapshotError>;

    fn handle(&mut self, msg: messages::PartialSynchronization, ctx: &mut Self::Context) -> Self::Result {
        // locally import necessary modules
        use engine::vault::Key as PKey;
        use serde::{Deserialize, Serialize};

        // define local snapshot data structure to access the private fields
        #[derive(Deserialize, Serialize, Default)]
        struct SnapshotStateLocal(pub HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

        // TODO:
        // introduce record level granularity

        // load associated system snapshot
        let src_config = msg.source;
        let snapshot_data_source = Snapshot::read_from_name_or_path(
            src_config.filename.as_deref(),
            src_config.path.as_deref(),
            src_config.key,
        )
        .map_err(|err| SnapshotError::SynchronizeSnapshot(err.to_string()))?;

        // load snapshot file for comparison
        // FIXME: this should be the current state of the secureactor
        let cmp_config = msg.compare;
        let snapshot_data_compare = Snapshot::read_from_name_or_path(
            cmp_config.filename.as_deref(),
            cmp_config.path.as_deref(),
            cmp_config.key,
        )
        .map_err(|err| SnapshotError::SynchronizeSnapshot(err.to_string()))?;

        // set snapshot file to be synchronized with
        let dst_config = msg.destination;

        // load the local state (or TODO: refill from current state)
        let local_state: SnapshotStateLocal = bincode::deserialize(&snapshot_data_source)
            .map_err(|err| SnapshotError::DeserializationFailure(err.to_string()))?;

        // load comparison snapshot and handle partial synchronization
        match bincode::deserialize::<SnapshotStateLocal>(&snapshot_data_compare) {
            Ok(compare_state) => {
                // create new snapshot to write
                let mut output_state = SnapshotState::default();

                // collect all allowed entries as passed by message
                let mut output_data = local_state.0;

                let compare = compare_state.0;

                // add all allowed entries to the output
                msg.allowed
                    .iter()
                    .filter(|id| compare.get(id).is_some())
                    .for_each(|id| {
                        output_data.insert(*id, compare.get(id).unwrap().clone());
                    });

                // add all local state to the output
                output_data.keys().for_each(|id| {
                    output_state.add_data(*id, compare.get(id).unwrap().clone());
                });

                // set current state
                self.state = output_state;

                let write_msg = WriteSnapshot {
                    key: dst_config.key,
                    filename: dst_config.filename,
                    path: dst_config.path,
                };

                // write the new state to disk
                <Self as Handler<WriteSnapshot>>::handle(self, write_msg, ctx)?;

                if dst_config.generates_output {
                    return Ok(Some(self.state.serialize()));
                }

                Ok(None)
            }
            Err(e) => Err(SnapshotError::SynchronizeSnapshot(e.to_string())),
        }
    }
}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = Result<(), anyhow::Error>;

    fn handle(&mut self, msg: messages::FillSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.state.add_data(msg.id, *msg.data);

        Ok(())
    }
}

impl Handler<messages::ReadFromSnapshot> for Snapshot {
    type Result = Result<returntypes::ReturnReadSnapshot, anyhow::Error>;

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
            match Snapshot::read_from_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key) {
                Ok(mut snapshot) => {
                    let data = snapshot.get_state(id);
                    *self = snapshot;

                    Ok(ReturnReadSnapshot {
                        id,
                        data: Box::new(data),
                    })
                }
                Err(_) => Err(anyhow::anyhow!(SnapshotError::LoadFailure)),
            }
        }
    }
}

impl Handler<messages::WriteSnapshot> for Snapshot {
    type Result = Result<(), SnapshotError>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)
            .expect(line_error!());

        self.state = SnapshotState::default();

        Ok(())
    }
}

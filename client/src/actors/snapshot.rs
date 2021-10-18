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
    internals,
    state::{
        secure::Store,
        snapshot::{ReadSnapshotError, Snapshot, SnapshotState, WriteSnapshotError},
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
        type Result = Result<(), WriteSnapshotError>;
    }

    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = ();
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
        type Result = Result<returntypes::ReturnReadSnapshot, ReadSnapshotError>;
    }
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    // #[error("Could Not Load Snapshot. Try another password")]
// Engine(#[from] engine::Error),
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
    type Result = Result<returntypes::ReturnReadSnapshot, ReadSnapshotError>;

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
    type Result = Result<(), WriteSnapshotError>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;

        self.state = SnapshotState::default();

        Ok(())
    }
}

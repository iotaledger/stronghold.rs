// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use actix::{Actor, Handler, Message, Supervised};

use std::path::PathBuf;

use engine::{snapshot, vault::ClientId};

use crate::state::snapshot::{Snapshot, SnapshotError};

/// re-export local modules
pub use messages::*;
pub use returntypes::*;

pub mod returntypes {

    use crate::state::snapshot::ClientState;

    use super::*;

    /// Return type for loaded snapshot file
    pub struct ReturnClientState {
        pub id: ClientId,

        pub data: Box<ClientState>,
    }
}

pub mod messages {

    use crate::{
        state::snapshot::{ClientState, UseKey},
        Location,
    };

    use super::*;

    pub struct WriteSnapshot {
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub key: UseKey,
    }

    impl Message for WriteSnapshot {
        type Result = Result<(), SnapshotError>;
    }

    pub struct FillSnapshot {
        pub data: Box<ClientState>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = Result<(), SnapshotError>;
    }

    pub struct ReadSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub key_location: Option<Location>,
    }

    impl Message for ReadSnapshot {
        type Result = Result<(), SnapshotError>;
    }

    pub struct LoadFromSnapshotState {
        pub id: ClientId,
    }

    impl Message for LoadFromSnapshotState {
        type Result = Result<returntypes::ReturnClientState, SnapshotError>;
    }
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

// actix impl
impl Supervised for Snapshot {}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = Result<(), SnapshotError>;

    fn handle(&mut self, msg: messages::FillSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.add_data(msg.id, *msg.data)
    }
}

impl Handler<messages::ReadSnapshot> for Snapshot {
    type Result = Result<(), SnapshotError>;

    /// This will try to read from a snapshot on disk, otherwise load from a local snapshot
    /// in memory. Returns the loaded snapshot data, that must be loaded inside the client
    /// for access.
    fn handle(&mut self, msg: messages::ReadSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        let key_location = msg.key_location.map(|loc| loc.resolve());
        *self = Snapshot::read_from_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key, key_location)?;
        Ok(())
    }
}

impl Handler<messages::LoadFromSnapshotState> for Snapshot {
    type Result = Result<returntypes::ReturnClientState, SnapshotError>;

    /// This will try to read from a snapshot on disk, otherwise load from a local snapshot
    /// in memory. Returns the loaded snapshot data, that must be loaded inside the client
    /// for access.
    fn handle(&mut self, msg: messages::LoadFromSnapshotState, _ctx: &mut Self::Context) -> Self::Result {
        let data = self.get_state(msg.id)?;

        Ok(ReturnClientState {
            id: msg.id,
            data: Box::new(data),
        })
    }
}

impl Handler<messages::WriteSnapshot> for Snapshot {
    type Result = Result<(), SnapshotError>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)?;

        *self = Snapshot::default();

        Ok(())
    }
}

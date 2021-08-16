// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use actix::{Actor, Handler, Message, Supervised};

use std::path::PathBuf;

use engine::{
    snapshot,
    vault::{BoxProvider, ClientId, DbView, Key, VaultId},
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
    pub struct ReturnReadSnapshot<T: BoxProvider + Send + Sync + Clone + 'static + Unpin> {
        pub id: ClientId,

        // TODO this could be re-worked for generalized synchronisation facilities
        // see crate::actors::secure::
        pub data: Box<(HashMap<VaultId, Key<T>>, DbView<T>, Store)>,
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
        type Result = Result<(), anyhow::Error>;
    }

    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    impl Message for FillSnapshot {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Default)]
    pub struct ReadFromSnapshot<T: BoxProvider + Send + Sync + Clone + 'static + Unpin> {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub id: ClientId,
        pub fid: Option<ClientId>,

        // phantom
        pub p: core::marker::PhantomData<T>,
    }

    impl<T> Message for ReadFromSnapshot<T>
    where
        T: BoxProvider + Send + Sync + Clone + 'static + Unpin,
    {
        type Result = Result<returntypes::ReturnReadSnapshot<T>, anyhow::Error>;
    }
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("Could Not Load Snapshot. Try another password")]
    LoadFailure,
}

// actix impl
impl Supervised for Snapshot {}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = Result<(), anyhow::Error>;

    fn handle(&mut self, msg: messages::FillSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.state.add_data(msg.id, *msg.data);

        Ok(())
    }
}

impl Handler<messages::ReadFromSnapshot<internals::Provider>> for Snapshot {
    type Result = Result<returntypes::ReturnReadSnapshot<internals::Provider>, anyhow::Error>;

    /// This will try to read from a snapshot on disk, otherwise load from a local snapshot
    /// in memory. Returns the loaded snapshot data, that must be loaded inside the client
    /// for access.
    fn handle(
        &mut self,
        msg: messages::ReadFromSnapshot<internals::Provider>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
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
    type Result = Result<(), anyhow::Error>;

    fn handle(&mut self, msg: messages::WriteSnapshot, _ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)
            .expect(line_error!());

        self.state = SnapshotState::default();

        Ok(())
    }
}

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::snapshot;

use crate::{
    actors::{InternalMsg, InternalResults},
    client::ClientMsg,
    line_error,
    snapshot::{Snapshot, SnapshotData},
    utils::StatusMessage,
};

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshot(
        snapshot::Key,
        Option<String>,
        Option<PathBuf>,
        (Vec<u8>, Vec<u8>),
        String,
    ),
    ReadSnapshot(snapshot::Key, Option<String>, Option<PathBuf>, String),
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new(None)
    }
}

impl Actor for Snapshot {
    type Msg = SMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<SMsg> for Snapshot {
    type Msg = SMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            SMsg::WriteSnapshot(key, name, path, (cache, store), cid) => {
                let snapshotdata = SnapshotData::new(cache, store);
                let snapshot = Snapshot::new(Some(snapshotdata));

                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                snapshot.write_to_snapshot(&path, key);

                let internal = ctx.select(&format!("/user/{}/", cid)).expect(line_error!());

                internal.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnWriteSnap(StatusMessage::Ok)),
                    sender,
                );
            }
            SMsg::ReadSnapshot(key, name, path, cid) => {
                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                let snapshot = Snapshot::read_from_snapshot(&path, key);

                let internal = ctx.select(&format!("/user/internal-{}/", cid)).expect(line_error!());

                let data: SnapshotData = snapshot.get_state();
                let cache: Vec<u8> = data.get_cache();
                let store: Vec<u8> = data.get_store();

                internal.try_tell(InternalMsg::ReloadData(cache, store, StatusMessage::Ok), sender);
            }
        }
    }
}

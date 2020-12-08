// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use runtime::zone::soft;

use crate::{actors::InternalMsg, line_error, snapshot::Snapshot, Provider, VaultId};

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshot(Vec<u8>, Option<String>, Option<PathBuf>, Vec<u8>),
    ReadSnapshot(Vec<u8>, Option<String>, Option<PathBuf>),
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new::<Provider>(vec![])
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

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            SMsg::WriteSnapshot(pass, name, path, state) => {
                let snapshot = Snapshot::new::<Provider>(state);

                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                snapshot.write_to_snapshot(&path, pass);
            }
            SMsg::ReadSnapshot(pass, name, path) => {
                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                let snapshot = Snapshot::read_from_snapshot::<Provider>(&path, pass);

                let bucket = ctx.select("/user/internal-actor/").expect(line_error!());
                bucket.try_tell(InternalMsg::ReloadData(snapshot.get_state()), None);
            }
        }
    }
}

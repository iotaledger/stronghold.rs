// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::snapshot;

use engine::vault::{Key, ReadResult};

use crate::{
    actors::{InternalMsg, SHResults},
    client::Client,
    line_error,
    snapshot::{Snapshot, SnapshotState},
    utils::StatusMessage,
    ClientId, Provider, VaultId,
};

use std::collections::BTreeMap;

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshotAll {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        data: (
            Client,
            BTreeMap<VaultId, Key<Provider>>,
            BTreeMap<Key<Provider>, Vec<ReadResult>>,
        ),
        id: ClientId,
        is_final: bool,
    },
    ReadFromSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        id: ClientId,
        fid: Option<ClientId>,
    },
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new(SnapshotState::default())
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
            SMsg::WriteSnapshotAll {
                key,
                filename,
                path,
                data,
                id,
                is_final,
            } => {
                let (client, store, cache) = data;

                self.state.ids.push(id);
                self.state.clients.push(client);
                self.state.stores.push(store);
                self.state.caches.push(cache);

                if is_final {
                    let path = if let Some(p) = path {
                        p
                    } else {
                        Snapshot::get_snapshot_path(filename)
                    };

                    self.clone().write_to_snapshot(&path, key);

                    self.state = SnapshotState::default();

                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnWriteSnap(StatusMessage::OK), None)
                        .expect(line_error!());
                } else {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnWriteSnap(StatusMessage::OK), None)
                        .expect(line_error!());
                }
            }
            SMsg::ReadFromSnapshot {
                key,
                filename,
                path,
                id,
                fid,
            } => {
                let id_str: String = id.into();
                let internal = ctx.select(&format!("/user/internal-{}/", id_str)).expect(line_error!());

                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(filename)
                };

                let cid = if let Some(fid) = fid { fid } else { id };

                match Snapshot::read_from_snapshot(&path, key) {
                    Ok(snapshot) => {
                        *self = snapshot.clone();

                        let data = snapshot.get_state(cid);

                        internal.try_tell(InternalMsg::ReloadData(data, StatusMessage::OK), sender);
                    }
                    Err(e) => {
                        sender
                            .as_ref()
                            .expect(line_error!())
                            .try_tell(
                                SHResults::ReturnReadSnap(StatusMessage::Error(format!(
                                    "{}, Unable to read snapshot. Please try another password.",
                                    e
                                ))),
                                None,
                            )
                            .expect(line_error!());
                    }
                };
            }
        }
    }
}

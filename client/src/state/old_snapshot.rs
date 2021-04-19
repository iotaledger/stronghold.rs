// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{self, read_from, write_to, Key},
    vault::nvault::DbView,
    vault::{ClientId, DBView, Key as PKey, PreparedRead, ReadResult, RecordHint, RecordId, VaultId},
};

use crate::{line_error, state::client::Store, Provider};

use std::path::Path;

use std::collections::HashMap;

#[derive(Clone)]
pub struct OldSnapshot {
    pub state: OldSnapshotState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub client_id: ClientId,
    pub vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    heads: Vec<RecordId>,
    counters: Vec<usize>,
    store: Store,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug)]
pub struct OldSnapshotState(
    HashMap<
        ClientId,
        (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    >,
);

impl OldSnapshot {
    /// Creates a new `OldSnapshot` from a buffer of `Vec<u8>` state.
    pub fn new(state: OldSnapshotState) -> Self {
        Self { state }
    }

    pub fn get_state(
        &mut self,
        id: ClientId,
    ) -> (
        Client,
        HashMap<VaultId, PKey<Provider>>,
        HashMap<VaultId, Vec<ReadResult>>,
    ) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (Client::new(id), HashMap::default(), HashMap::default()),
        }
    }

    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<Self> {
        let state = match path {
            Some(p) => read_from(p, &key, &[])?,
            None => read_from(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let data = OldSnapshotState::deserialize(state);

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(self, name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<()> {
        let data = self.state.serialize();

        // TODO: This is a hack and probably should be removed when we add proper error handling.
        let f = move || {
            match path {
                Some(p) => write_to(&data, p, &key, &[])?,
                None => write_to(&data, &snapshot::files::get_path(name)?, &key, &[])?,
            }
            Ok(())
        };
        match f() {
            Ok(()) => Ok(()),
            Err(_) => f(),
        }
    }
}

impl OldSnapshotState {
    pub fn new(
        id: ClientId,
        data: (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    ) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    pub fn add_data(
        &mut self,
        id: ClientId,
        data: (
            Client,
            HashMap<VaultId, PKey<Provider>>,
            HashMap<VaultId, Vec<ReadResult>>,
        ),
    ) {
        self.0.insert(id, data);
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }

    pub fn convert(self) -> HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)> {
        let mut data = HashMap::new();

        self.0.into_iter().for_each(|(cid, (cl, key_store, reads))| {
            let mut vrecord: HashMap<VaultId, Vec<RecordId>> = HashMap::new();
            let mut v = DbView::<Provider>::new();

            cl.vaults.into_iter().for_each(|(vid, (_, rid))| {
                vrecord.insert(vid, rid);
            });

            key_store.iter().for_each(|(vid, key)| {
                if let Some(rds) = reads.get(&vid) {
                    let view = DBView::load(key.clone(), rds.into_iter()).expect(line_error!());
                    let hints: Vec<(RecordId, RecordHint)> = view.records().collect();
                    let reader = view.reader();

                    if let Some(rids) = vrecord.get(&vid) {
                        rids.into_iter().for_each(|rid| {
                            let read = reader.prepare_read(rid).expect(line_error!());

                            if let Some((_, hint)) = hints.iter().find(|(r, _)| r == rid) {
                                if let PreparedRead::CacheHit(data) = read {
                                    v.write(&key, *vid, *rid, &data, *hint).expect(line_error!());
                                }
                            }
                        });
                    }
                };
            });

            data.insert(cid, (key_store, v, cl.store));
        });

        data
    }
}

impl Client {
    pub fn new(client_id: ClientId) -> Self {
        let vaults = HashMap::new();
        let heads = vec![];

        let counters = vec![0];
        let store = Store::new();

        Self {
            client_id,
            vaults,
            heads,
            counters,
            store,
        }
    }
}

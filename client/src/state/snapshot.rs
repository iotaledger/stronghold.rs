// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use serde::{Deserialize, Serialize};

use engine::{
    snapshot::{self, read_from, write_to, Key},
    vault::{ClientId, DbView, Key as PKey, VaultId},
};

use crate::{line_error, state::client::Store, Provider};

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

/// Wrapper for the [`SnapshotState`] data structure.
pub struct Snapshot {
    pub state: SnapshotState,
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(HashMap<ClientId, (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)>);

impl Snapshot {
    /// Creates a new [`Snapshot`] from a buffer of [`SnapshotState`] state.
    pub fn new(state: SnapshotState) -> Self {
        Self { state }
    }

    /// Gets the state component parts as a tuple.
    pub fn get_state(&mut self, id: ClientId) -> (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store) {
        match self.state.0.remove(&id) {
            Some(t) => t,
            None => (HashMap::default(), DbView::default(), Store::default()),
        }
    }

    /// Checks to see if the [`ClientId`] exists in the snapshot hashmap.
    pub fn has_data(&self, cid: ClientId) -> bool {
        self.state.0.contains_key(&cid)
    }

    /// Synchronizes this [`Snapshot`] with another and writes it to provided target path.
    pub fn synchronize(
        &self,
        other_path: Option<&Path>,
        other_filename: Option<&str>,
        other_key: Key,
        target_path: PathBuf,
        target_key: Key,
    ) -> crate::Result<()> {
        // load other
        let other = Self::read_from_snapshot(other_filename, other_path, other_key)?;

        // get states
        let state_a = &self.state.0;
        let state_b = &other.state.0;

        let mut result = HashMap::new();

        // primitive union of two snapshots, does not check for
        // different versions etc...
        state_a.iter().for_each(|(id, value)| {
            result.insert(*id, value.clone());
        });

        state_b.iter().for_each(|(id, value)| {
            result.insert(*id, value.clone());
        });

        let state = SnapshotState(result);
        let plain = state.serialize();

        write_to(&plain, target_path.as_path(), &target_key, &[])
            .expect("Failed to write synchronized snapshot to disk.");

        Ok(())
    }

    /// Reads a snapshot from provided path
    pub fn read_snapshot_with_full_path<P>(path: P, key: &Key) -> crate::Result<Self>
    where
        P: AsRef<Path>,
    {
        let data = SnapshotState::deserialize(read_from(path.as_ref(), &key, &[])?);
        Ok(Self::new(data))
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<Self> {
        let state = match path {
            Some(p) => read_from(p, &key, &[])?,
            None => read_from(&snapshot::files::get_path(name)?, &key, &[])?,
        };

        let data = SnapshotState::deserialize(state);

        Ok(Self::new(data))
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn write_to_snapshot(&self, name: Option<&str>, path: Option<&Path>, key: Key) -> crate::Result<()> {
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

impl SnapshotState {
    /// Creates a new snapshot state.
    pub fn new(id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) -> Self {
        let mut state = HashMap::new();
        state.insert(id, data);

        Self(state)
    }

    /// Adds data to the snapshot state hashmap.
    pub fn add_data(&mut self, id: ClientId, data: (HashMap<VaultId, PKey<Provider>>, DbView<Provider>, Store)) {
        self.0.insert(id, data);
    }

    /// Serializes the snapshot state into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect(line_error!())
    }

    /// Deserializes the snapshot state from bytes.
    pub fn deserialize(data: Vec<u8>) -> Self {
        bincode::deserialize(&data).expect(line_error!())
    }
}

mod sync {
    #![allow(clippy::all)]
    #![allow(dead_code, unused_variables)]

    use crate::state::client::Client;

    pub use super::*;
    use engine::vault::RecordId;
    use serde::Serialize;

    use thiserror::Error as DeriveError;

    // use engine::snapshot::diff::*;

    #[derive(Debug, DeriveError)]
    pub enum SyncError {
        #[error("Types incompatible")]
        TypesIncompatible,
    }

    pub struct Chunk<T>
    where
        T: Clone,
    {
        data: Vec<T>,
    }

    impl<T> Chunk<T>
    where
        T: Clone,
    {
        pub fn into_chunks(&mut self, input: T) -> impl Iterator<Item = &T> {
            self.data.extend_from_slice(vec![input].as_slice());
            self.data.iter()
        }
    }

    /// Default impl for [`SynchronizePolicy`]
    /// The defaulted policy is [`SynchronizePolicy::Deny`]
    pub enum SynchronizePolicy {
        Allow,
        Deny,
    }

    pub enum EntryType {
        RecordId(RecordId),
        VaultId(VaultId),
        ClientId(Client),
    }

    impl Default for SynchronizePolicy {
        fn default() -> Self {
            SynchronizePolicy::Deny
        }
    }

    pub trait Bootstrap<T>: Serialize
    where
        T: Serialize + AsRef<EntryType>,
    {
        fn with_chunks<C>(self, chunks: Vec<Chunk<C>>) -> Self
        where
            C: Clone;

        fn with_key<K>(self, key: K) -> Self
        where
            K: Into<Key>;

        fn allow<Y>(self, policy: Y, target_id: T) -> Self
        where
            Y: AsRef<SynchronizePolicy>;

        fn deny<Y>(self, policty: Y, target_id: T) -> Self
        where
            Y: AsRef<SynchronizePolicy>;
    }

    pub trait Synchronize<T>: Bootstrap<T>
    where
        T: Serialize + AsRef<EntryType>,
    {
        fn lazy<I>(&self, other: T) -> I
        where
            I: Iterator;

        fn full(&self, other: T) -> Result<T, SyncError>;

        fn partial<Y>(&self, other: T, policy: Y) -> Result<T, SyncError>
        where
            Y: AsRef<SynchronizePolicy>;
    }

    // #[derive(Serialize)]
    // pub struct Local<P, T>
    // where
    //     P: AsRef<Path> + Serialize,
    //     T: Serialize + AsRef<EntryType>,
    // {
    //     storage_location: P,
    //     data: T,
    // }

    // impl<P, T> Local<P, T>
    // where
    //     P: AsRef<Path> + Serialize,
    //     T: Serialize + AsRef<EntryType>,
    // {
    //     fn with_target(path: P, this: T) -> Self {
    //         todo!()
    //     }
    // }

    // impl<T, P> Bootstrap<T> for Local<P, T>
    // where
    //     P: AsRef<Path> + Serialize,
    //     T: Serialize + AsRef<EntryType>,
    // {
    //     fn with_chunks<C>(self, chunks: Vec<Chunk<C>>) -> Self
    //     where
    //         C: Clone,
    //     {
    //         todo!()
    //     }

    //     fn with_key<K>(self, key: K) -> Self
    //     where
    //         K: Into<Key>,
    //     {
    //         todo!()
    //     }

    //     fn allow<Y>(self, policy: Y, target_id: T) -> Self
    //     where
    //         Y: AsRef<SynchronizePolicy>,
    //     {
    //         todo!()
    //     }

    //     fn deny<Y>(self, policty: Y, target_id: T) -> Self
    //     where
    //         Y: AsRef<SynchronizePolicy>,
    //     {
    //         todo!()
    //     }
    // }

    // impl<K, T> Synchronize<T> for K
    // where
    //     T: Serialize,
    //     K: Bootstrap<T> + Serialize,
    // {
    //     fn lazy<I>(&self, other: T) -> I
    //     where
    //         I: Iterator,
    //     {
    //         todo!()
    //     }

    //     fn full(&self, other: T) -> Result<T, SyncError> {
    //         todo!()
    //     }

    //     fn partial<Y>(&self, other: T, policy: Y) -> Result<T, SyncError>
    //     where
    //         Y: AsRef<SynchronizePolicy>,
    //     {
    //         todo!()
    //     }
    // }

    #[cfg(test)]
    mod tests {

        use super::*;

        #[derive(Serialize, Default)]
        struct Container {}

        #[test]
        fn test_synchronize() {
            // let a = Container::default();
            // let b = Container::default();

            // let local_sync = Local::with_target("/path/to/snapshot.stronghold", a).with_key([0u8; 32]);

            // local_sync.allow(SynchronizePolicy::Allow, b"non-secret-record-id");
            // assert!(local_sync.full(b).is_ok());
        }
    }
}

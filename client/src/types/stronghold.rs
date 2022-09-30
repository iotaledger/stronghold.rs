// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{
    procedures::Runner,
    sync::{SnapshotHierarchy, SyncSnapshots, SyncSnapshotsConfig},
    Client, ClientError, ClientState, KeyProvider, LoadFromPath, Location, RemoteMergeError, RemoteVaultError,
    Snapshot, SnapshotPath, Store, UseKey,
};
use crypto::keys::x25519;
use engine::vault::ClientId;
use std::{
    collections::{hash_map::Entry, HashMap},
    ops::Deref,
    sync::{Arc, RwLock, RwLockWriteGuard},
};
use stronghold_utils::GuardDebug;
use zeroize::Zeroize;

/// The Stronghold is a secure storage for sensitive data. Secrets that are stored inside
/// a Stronghold can never be read, but only be accessed via cryptographic procedures. Data inside
/// a Stronghold is heavily protected by the `Runtime` by either being encrypted at rest, having
/// kernel supplied memory guards, that prevent memory dumps, or a combination of both. The Stronghold
/// also persists data written into a Stronghold by creating Snapshots of the current state. The
/// Snapshot itself is encrypted and can be accessed by a key.
#[derive(Default, Clone, GuardDebug)]
pub struct Stronghold {
    /// a reference to the [`Snapshot`]
    snapshot: Arc<RwLock<Snapshot>>,

    /// A map of [`ClientId`] to [`Client`]s
    clients: Arc<RwLock<HashMap<ClientId, Client>>>,

    // A per Stronghold session store
    store: Store,

    /// Optional key location for writing to [`Snapshot`]
    key_location: Arc<RwLock<Option<Location>>>,
}

impl Stronghold {
    /// Drop all references
    ///
    /// # Example
    pub fn reset(self) -> Self {
        Self::default()
    }

    /// Returns an atomic reference to the [`Store`]
    pub fn store(&self) -> Store {
        self.store.clone()
    }

    /// Load the state of a [`Snapshot`] at given `snapshot_path`.
    ///
    /// The [`Snapshot`] is secured in memory and may be used to load further
    /// clients with [`Stronghold::load_client`].
    /// Load a [`Client`] at `client_path` from the snapshot.
    /// The function returns an error if the client path is not in the snapshot
    /// or a client with the same id has already been loaded before.
    pub fn load_client_from_snapshot<P>(
        &self,
        client_path: P,
        keyprovider: &KeyProvider,
        snapshot_path: &SnapshotPath,
    ) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let mut client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        // If a client has already been loaded returns an error
        let mut clients = self.clients.try_write()?;
        if clients.contains_key(&client_id) {
            return Err(ClientError::ClientAlreadyLoaded(client_id));
        }

        // load the snapshot from disk
        self.load_snapshot(keyprovider, snapshot_path)?;

        let snapshot = self.snapshot.try_read()?;

        let client_state: ClientState = snapshot
            .get_state(client_id)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        drop(snapshot);

        // Load the client state
        client.restore(client_state, client_id)?;

        // insert client as ref into Strongholds client ref
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Loads a client from [`Snapshot`] data
    ///
    /// The function returns an error if the client path is not in the snapshot
    /// or a client with the same id has already been loaded before.
    pub fn load_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        let mut client = Client::default();

        // If a client has already been loaded returns an error
        let mut clients = self.clients.try_write()?;
        if clients.contains_key(&client_id) {
            return Err(ClientError::ClientAlreadyLoaded(client_id));
        }

        let snapshot = self.snapshot.try_read()?;

        if !snapshot.has_data(client_id) {
            return Err(ClientError::ClientDataNotPresent);
        }

        let client_state: ClientState = snapshot
            .get_state(client_id)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        drop(snapshot);

        // Load the client state
        client.restore(client_state, client_id)?;

        // insert client as ref into Strongholds client ref
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Returns an in session client, not being persisted in a [`Snapshot`]
    ///
    /// # Example
    pub fn get_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        let clients = self.clients.try_read()?;
        clients
            .get(&client_id)
            .cloned()
            .ok_or(ClientError::ClientDataNotPresent)
    }

    /// Unload the client from the clients currently managed by
    /// the [`Stronghold`] instance
    ///
    /// This does not remove the client from the [`Snapshot`]
    pub fn unload_client(&self, client: Client) -> Result<Client, ClientError> {
        let mut clients = self.clients.try_write()?;
        clients.remove(&client.id).ok_or(ClientError::ClientDataNotPresent)
    }

    /// Purges a [`Client`] by wiping all state and remove it from
    /// snapshot. This operation is destructive.
    ///
    /// # Example
    pub fn purge_client(&self, client: Client) -> Result<(), ClientError> {
        let mut clients = self.clients.try_write()?;
        clients.remove(client.id());

        let mut snapshot = self.snapshot.try_write()?;
        snapshot
            .purge_client(*client.id())
            .map_err(|e| ClientError::Inner(e.to_string()))
    }

    /// Load the state of a [`Snapshot`] at given `snapshot_path`. The [`Snapshot`]
    /// is secured in memory.
    ///
    /// # Example
    pub fn load_snapshot(&self, keyprovider: &KeyProvider, snapshot_path: &SnapshotPath) -> Result<(), ClientError> {
        let mut snapshot = self.snapshot.try_write()?;

        if !snapshot_path.exists() {
            let path = snapshot_path
                .as_path()
                .to_str()
                .ok_or_else(|| ClientError::Inner("Cannot display path as string".to_string()))?;

            return Err(ClientError::SnapshotFileMissing(path.to_string()));
        }

        // CRITICAL SECTION
        let buffer = keyprovider
            .try_unlock()
            .map_err(|e| ClientError::Inner(format!("{:?}", e)))?;
        let buffer_ref = buffer.borrow().deref().try_into().unwrap();

        *snapshot = Snapshot::read_from_snapshot(snapshot_path, buffer_ref, None)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        drop(snapshot);
        // END CRITICAL SECTION

        Ok(())
    }

    /// Returns a reference to the local [`Snapshot`]
    ///
    /// # Example
    pub fn get_snapshot(&self) -> Result<RwLockWriteGuard<Snapshot>, ClientError> {
        let snapshot = self.snapshot.try_write()?;

        Ok(snapshot)
    }

    /// Stores the key to write to the [`Snapshot`] at [`Location`]. This operation zeroizes the key
    /// after successful insertion
    pub fn store_snapshot_key_at_location(&self, key: KeyProvider, location: Location) -> Result<(), ClientError> {
        let key = key.try_unlock().map_err(|e| ClientError::Inner(e.to_string()))?;

        let mut key_location = self.key_location.write().map_err(|e| ClientError::LockAcquireFailed)?;
        key_location.replace(location.clone());

        let mut snapshot = self.get_snapshot()?;
        let mut kkey = [0u8; 32];

        let key = key.borrow();
        kkey.copy_from_slice(key.as_ref());

        snapshot.store_secret_key(kkey, location)?;

        Ok(())
    }

    /// Creates a new, empty [`Client`]
    ///
    /// # Example
    pub fn create_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        let client = Client {
            id: client_id,
            ..Default::default()
        };

        // insert client as ref into Strongholds client ref
        let mut clients = self.clients.try_write()?;
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Writes all client states into the [`Snapshot`] file using the `KeyProvider` to
    /// encrypt the [`Snapshot`] file.
    pub fn commit_with_keyprovider(
        &self,
        snapshot_path: &SnapshotPath,
        keyprovider: &KeyProvider,
    ) -> Result<(), ClientError> {
        let clients = self.clients.try_read()?;

        if !snapshot_path.exists() {
            let path = snapshot_path.as_path().parent().ok_or_else(|| {
                ClientError::SnapshotFileMissing("Parent directory of snapshot file does not exist".to_string())
            })?;
            if let Err(io_error) = std::fs::create_dir_all(path) {
                return Err(ClientError::SnapshotFileMissing(
                    "Could not create snapshot file".to_string(),
                ));
            }
        }

        let ids: Vec<ClientId> = clients.iter().map(|(id, _)| *id).collect();
        drop(clients);

        for client_id in ids {
            self.write(client_id)?;
        }

        let snapshot = self.snapshot.try_read()?;

        // CRITICAL SECTION
        let buffer = keyprovider
            .try_unlock()
            .map_err(|e| ClientError::Inner(format!("{:?}", e)))?;
        let buffer_ref = buffer.borrow();
        let key = buffer_ref.deref();

        snapshot
            .write_to_snapshot(snapshot_path, UseKey::Key(key.try_into().unwrap()))
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        Ok(())
    }

    /// Writes all client states into the [`Snapshot`] file
    ///
    /// # Example
    pub fn commit(&self, snapshot_path: &SnapshotPath) -> Result<(), ClientError> {
        let clients = self.clients.try_read()?;

        if !snapshot_path.exists() {
            let path = snapshot_path.as_path().parent().ok_or_else(|| {
                ClientError::SnapshotFileMissing("Parent directory of snapshot file does not exist".to_string())
            })?;
            if let Err(io_error) = std::fs::create_dir_all(path) {
                return Err(ClientError::SnapshotFileMissing(
                    "Could not create snapshot file".to_string(),
                ));
            }
        }

        let ids: Vec<ClientId> = clients.iter().map(|(id, _)| *id).collect();
        drop(clients);

        for client_id in ids {
            self.write(client_id)?;
        }

        let snapshot = self.snapshot.try_read()?;

        // CRITICAL SECTION
        let loc = self.key_location.read().map_err(|_| ClientError::LockAcquireFailed)?;

        let key_location = match &*loc {
            Some(key_location) => key_location,
            None => return Err(ClientError::SnapshotKeyLocationMissing),
        };

        snapshot
            .write_to_snapshot(snapshot_path, UseKey::Stored(key_location.clone()))
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        Ok(())
    }

    /// Writes the state of a single client into [`Snapshot`] data
    ///
    /// # Example
    pub fn write_client<P>(&self, client_path: P) -> Result<(), ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        self.write(client_id)
    }

    /// Writes a single [`Client`] into snapshot
    ///
    /// # Example
    fn write(&self, client_id: ClientId) -> Result<(), ClientError> {
        let mut snapshot = self.snapshot.try_write()?;
        let clients = self.clients.try_read()?;

        let client = match clients.get(&client_id) {
            Some(client) => client,
            None => return Err(ClientError::ClientDataNotPresent),
        };

        let mut keystore_guard = client.keystore.try_write()?;

        let view = client.db.try_read()?;
        let store = client.store.cache.try_read()?;

        // we need some compatibility code here. Keyprovider stores encrypted vec
        // by snapshot requires a mapping to Key<Provider>

        let keystore = keystore_guard.get_data();
        drop(keystore_guard);

        // This might be critical, as keystore gets copied into Boxed types, but still safe
        // we also use cloned data, which might not be ideal.
        snapshot
            .add_data(client_id, (keystore, (*view).clone(), (*store).clone()))
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        Ok(())
    }

    /// Calling this function clears the runtime state of all [`Client`]s and the in-memory
    /// [`Snapshot`] state. This does not affect the persisted [`Client`] state inside a
    /// snapshot file. Use [`Self::load_client_from_snapshot`] to reload any [`Client`] and
    /// [`Snapshot`] state
    pub fn clear(&self) -> Result<(), ClientError> {
        let mut clients = self.clients.try_write()?;
        for (_, client) in clients.drain() {
            client.clear()?;
        }
        self.snapshot.try_write()?.clear()?;
        self.store.clear()?;

        Ok(())
    }
}

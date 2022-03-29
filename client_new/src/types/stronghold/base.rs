// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Client, ClientError, ClientState, KeyProvider, LoadFromPath, Snapshot, SnapshotPath, Stronghold, UseKey};
use engine::vault::ClientId;
use std::ops::Deref;

impl Stronghold {
    /// Drop all references
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub fn reset(self) -> Self {
        Self::default()
    }

    /// Load the state of a [`Snapshot`] at given `snapshot_path`.
    /// The [`Snapshot`] is secured in memory and may be used to load further
    /// clients with [`Stronghold::load_client`].
    /// Load a [`Client`] at `client_path` from the snapshot.
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub async fn load_client_from_snapshot<P>(
        &self,
        client_path: P,
        keyprovider: &KeyProvider,
        snapshot_path: &SnapshotPath,
    ) -> Result<Client, ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        let mut snapshot = self.snapshot.try_write().map_err(|_| ClientError::LockAcquireFailed)?;

        // CRITICAL SECTION
        let buffer = keyprovider
            .try_unlock()
            .map_err(|e| ClientError::Inner(format!("{:?}", e)))?;
        let buffer_ref = buffer.borrow().deref().try_into().unwrap();
        // let key = buffer_ref.deref();

        *snapshot = Snapshot::read_from_snapshot(snapshot_path, buffer_ref, None)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        // END CRITICAL SECTION

        let client_state: ClientState = snapshot
            .get_state(client_id)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        drop(snapshot);

        // Load the client state
        client.load(client_state, client_id).await?;

        // insert client as ref into Strongholds client ref
        let mut clients = self.clients.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        clients.insert(client_id, client.atomic_ref());

        Ok(client)
    }

    /// Loads a client from [`Snapshot`] data
    pub async fn load_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        let snapshot = self.snapshot.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        if !snapshot.has_data(client_id) {
            return Err(ClientError::ClientDataNotPresent);
        }

        let client_state: ClientState = snapshot
            .get_state(client_id)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        drop(snapshot);

        // Load the client state
        client.load(client_state, client_id).await?;

        // insert client as ref into Strongholds client ref
        let mut clients = self.clients.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        clients.insert(client_id, client.atomic_ref());

        Ok(client)
    }

    /// Creates a new, empty [`Client`]
    ///
    /// # Example
    pub async fn create_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        // insert client as ref into Strongholds client ref
        let mut clients = self.clients.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        clients.insert(client_id, client.atomic_ref());

        Ok(client)
    }

    /// Writes all client states into the [`Snapshot`] file
    ///
    /// # Example
    pub async fn commit(&self, snapshot_path: &SnapshotPath, keyprovider: &KeyProvider) -> Result<(), ClientError> {
        let clients = self.clients.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        let ids: Vec<ClientId> = clients.iter().map(|(id, _)| *id).collect();
        drop(clients);

        for client_id in ids {
            self.write(client_id).await?;
        }

        let snapshot = self.snapshot.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

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

    /// Writes the state of a single client into [`Snapshot`] data
    ///
    /// # Example
    pub async fn write_client<P>(&self, client_path: P) -> Result<(), ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        self.write(client_id).await
    }

    /// Writes a single [`Client`] into snapshot
    ///
    /// # Example
    async fn write(&self, client_id: ClientId) -> Result<(), ClientError> {
        let mut snapshot = self.snapshot.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        let clients = self.clients.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        let client = match clients.get(&client_id) {
            Some(client) => client,
            None => return Err(ClientError::ClientDataNotPresent),
        };

        let mut keystore_guard = client
            .keystore
            .try_write()
            .map_err(|_| ClientError::LockAcquireFailed)?;

        let view = client.db.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let store = client
            .store
            .cache
            .try_read()
            .map_err(|_| ClientError::LockAcquireFailed)?;

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
}

impl Drop for Stronghold {
    fn drop(&mut self) {}
}

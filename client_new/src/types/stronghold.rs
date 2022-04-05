// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// p2p Stronghold functionality
#[cfg(feature = "p2p")]
mod p2p_old;

#[cfg(feature = "p2p")]
pub mod network_old;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{
    procedures::Runner, Client, ClientError, ClientState, KeyProvider, LoadFromPath, Snapshot, SnapshotPath, Store,
    UseKey,
};
use engine::vault::ClientId;
#[cfg(feature = "p2p")]
use futures::{future, StreamExt};
#[cfg(feature = "p2p")]
pub use p2p_old::*;

#[cfg(feature = "p2p")]
use stronghold_p2p::{Executor, ListenErr, Multiaddr, PeerId};

#[cfg(feature = "p2p")]
use crate::network_old::Network;

#[cfg(feature = "p2p")]
use self::network_old::StrongholdNetworkResult;

use std::ops::Deref;

/// The Stronghold is a secure storage for sensitive data. Secrets that are stored inside
/// a Stronghold can never be read, but only be accessed via cryptographic procedures. Data inside
/// a Stronghold is heavily protected by the [`Runtime`] by either being encrypted at rest, having
/// kernel supplied memory guards, that prevent memory dumps, or a combination of both. The Stronghold
/// also persists data written into a Stronghold by creating Snapshots of the current state. The
/// Snapshot itself is encrypted and can be accessed by a key.
/// TODO: more epic description
#[derive(Default, Clone)]
pub struct Stronghold {
    /// a reference to the [`Snapshot`]
    snapshot: Arc<RwLock<Snapshot>>,

    /// A map of [`ClientId`] to [`Client`]s
    clients: Arc<RwLock<HashMap<ClientId, Client>>>,

    // A per Stronghold session store
    store: Store,

    #[cfg(feature = "p2p")]
    network: Arc<futures::lock::Mutex<Option<Network>>>,
}

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
    pub fn load_client_from_snapshot<P>(
        &self,
        client_path: P,
        keyprovider: &KeyProvider,
        snapshot_path: &SnapshotPath,
    ) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

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
        let mut clients = self.clients.try_write()?;
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Loads a client from [`Snapshot`] data
    ///
    /// # Example
    /// ```
    /// ```
    pub fn load_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

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
        let mut clients = self.clients.try_write()?;
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Returns an in session client, not being persisted in a [`Snapshot`]
    ///
    /// # Example
    /// ```
    /// ```
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

    /// Purges a [`Client`] by wiping all state and remove it from
    /// snapshot. This operation is destructive.
    ///
    /// # Example
    /// ```
    /// ```
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
    /// ```
    /// ```
    pub fn load_snapshot(&self, keyprovider: &KeyProvider, snapshot_path: &SnapshotPath) -> Result<(), ClientError> {
        let mut snapshot = self.snapshot.try_write()?;

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

    /// Creates a new, empty [`Client`]
    ///
    /// # Example
    /// ```
    /// ```
    pub fn create_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client = Client::default();
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        // insert client as ref into Strongholds client ref
        let mut clients = self.clients.try_write()?;
        clients.insert(client_id, client.clone());

        Ok(client)
    }

    /// Writes all client states into the [`Snapshot`] file
    ///
    /// # Example
    /// ```
    /// ```
    pub fn commit(&self, snapshot_path: &SnapshotPath, keyprovider: &KeyProvider) -> Result<(), ClientError> {
        let clients = self.clients.try_read()?;

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

    /// Writes the state of a single client into [`Snapshot`] data
    ///
    /// # Example
    /// ```
    /// ```
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
    /// ```
    /// ```
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
}

// networking functionality

#[cfg(feature = "p2p")]
impl Stronghold {
    // pub async fn spawn_p2p() {}

    /// Serve requests to remote Stronghold clients. This call is blocking.
    /// Accepts a receiver to terminate the listener.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn serve(&self, mut shutdown: futures::channel::oneshot::Receiver<()>) -> Result<(), ClientError> {
        let mut network = self.network.lock().await;

        let mut rx = network.as_mut().unwrap()._inbound_request_rx.take().unwrap();
        drop(network);

        // executor.exec(Box::pin(async move {
        loop {
            match shutdown.try_recv() {
                Ok(inner) => {
                    if inner.is_some() {
                        return Ok(());
                    }
                }
                Err(e) => return Err(ClientError::Inner(e.to_string())),
            };

            if let Some(inner) = rx.next().await {
                // handler function here
                match inner.request {
                    network_old::StrongholdRequest::ClientRequest { client_path, request } => {
                        // load client
                        let client = self.load_client(client_path).unwrap();

                        match request {
                            network_old::ClientRequest::CheckVault { vault_path } => {
                                let result = client.vault_exists(vault_path);

                                let tx = inner.response_tx;
                                tx.send(StrongholdNetworkResult::Bool(result.unwrap())).unwrap();
                            }
                            network_old::ClientRequest::CheckRecord { location } => todo!(),
                            network_old::ClientRequest::ListIds { vault_path } => todo!(),
                            network_old::ClientRequest::WriteToRemoteVault {
                                location,
                                payload,
                                hint,
                            } => {
                                let vault = client.vault(location.vault_path());
                                let result = vault.write_secret(location, payload);

                                let tx = inner.response_tx;
                                tx.send(StrongholdNetworkResult::Empty(())).unwrap();
                            }

                            network_old::ClientRequest::WriteToVault {
                                location,
                                payload,
                                hint,
                            } => todo!(),
                            network_old::ClientRequest::RevokeData { location } => todo!(),
                            network_old::ClientRequest::ReadFromStore { key } => todo!(),
                            network_old::ClientRequest::WriteToStore { key, payload, lifetime } => todo!(),
                            network_old::ClientRequest::DeleteFromStore { key } => todo!(),
                            network_old::ClientRequest::Procedures { procedures } => todo!(),
                        }
                    }
                    network_old::StrongholdRequest::SnapshotRequest { request } => {}
                }
            }
        }
    }

    /// Loads a remote [`Client`] and returns it.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_load_client(&self, peer: PeerId) -> Result<Client, ClientError> {
        todo!()
    }

    /// Start listening on the swarm to the given address. If no address is provided, it will be assigned by the OS.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn start_listening(&self, address: Option<Multiaddr>) -> Result<Multiaddr, ListenErr> {
        let mut network = self.network.lock().await;

        let network = match &mut *network {
            Some(network) => network,
            None => return Err(ListenErr::Shutdown), // wrong error
        };

        network.start_listenening(address).await
    }

    /// Stop listening on the swarm.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn stop_listening(&self) -> Result<(), ClientError> {
        let mut network = self.network.lock().await;

        let network = match &mut *network {
            Some(network) => network,
            None => {
                return Err(ClientError::NoValuePresent(
                    "Stronghold: Network value not present".to_string(),
                ))
            } // wrong error
        };

        network.stop_listening().await
    }
}

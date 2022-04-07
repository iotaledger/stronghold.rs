// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// p2p Stronghold functionality
#[cfg(feature = "p2p")]
mod p2p_old;

#[cfg(feature = "p2p")]
pub mod network_old;

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, RwLock},
};

use crate::{
    procedures::Runner, Client, ClientError, ClientState, KeyProvider, LoadFromPath, Location, Snapshot, SnapshotPath,
    Store, UseKey,
};

#[cfg(feature = "p2p")]
use crate::{Peer, SpawnNetworkError};

use engine::vault::ClientId;
#[cfg(feature = "p2p")]
use futures::{future, StreamExt};
#[cfg(feature = "p2p")]
pub use p2p_old::*;

#[cfg(feature = "p2p")]
use stronghold_p2p::{
    identity::{Keypair, PublicKey},
    InitKeypair,
};
#[cfg(feature = "p2p")]
use stronghold_p2p::{Executor, ListenErr, Multiaddr, PeerId};

#[cfg(feature = "p2p")]
use crate::network_old::Network;

#[cfg(feature = "p2p")]
use self::network_old::{ClientRequest, NetworkConfig, StrongholdNetworkResult};

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

    #[cfg(feature = "p2p")]
    peers: Arc<futures::lock::Mutex<HashMap<PeerId, Peer>>>,
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
    /// Processes [`ClientRequests`]
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn handle_client_request(&self, request: ClientRequest) -> Result<(), ClientError> {
        todo!()
    }

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

    /// Creates a [`Peer`] from a [`PublicKey`] and returns it.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn create_remote_client(&self, public_key: PublicKey) -> Result<Peer, ClientError> {
        let peer_id = public_key.to_peer_id();
        let mut peers = self.peers.lock().await;
        match peers.entry(peer_id) {
            Entry::Occupied(o) => Ok(o.get().clone()),
            Entry::Vacant(v) => {
                let peer = Peer::new(*v.key(), self.clone());
                v.insert(peer.clone());
                Ok(peer)
            }
        }
    }

    /// Creates a new empty [`Client`] with an identity [`Keypair`] stored at [`Location`]
    ///
    /// # Example
    /// ```
    /// ```
    pub fn create_client_with_keys<P>(
        &self,
        client_path: P,
        keypair: Keypair,
        location: Location,
    ) -> Result<Client, ClientError>
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

        // write the keypair into the loation in the vault
        client.write_p2p_keypair(keypair, location)?;

        Ok(client)
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
            }
        };

        network.stop_listening().await
    }

    /// Spawn the p2p-network actor and swarm.
    /// The `keypair`parameter can be provided as location in which a keypair is stored,
    /// (either via [`Client::generate_p2p_keypair`] or [`Client::write_p2p_keypair`]).
    /// A new noise [`AuthenticKeypair`] and the [`PeerId`] will be derived from this keypair and used
    /// for authentication and encryption on the transport layer.
    ///
    /// **Note**: The noise keypair differs for each derivation, the [`PeerId`] is consistent.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn spawn_p2p<P>(
        &self,
        client_path: P,
        network_config: NetworkConfig,
        keypair: Option<Location>,
    ) -> Result<(), SpawnNetworkError>
    where
        P: AsRef<[u8]>,
    {
        // could this result in a dead-lock?
        let mut network = self.network.lock().await;

        if network.is_some() {
            return Err(SpawnNetworkError::AlreadySpawned);
        }

        let client = match self
            .load_client(client_path.as_ref())
            .map_err(|_| SpawnNetworkError::ClientNotFound)
        {
            Ok(client) => client,
            Err(_) => match self.get_client(client_path) {
                Ok(client) => client,
                Err(e) => return Err(SpawnNetworkError::ClientNotFound),
            },
        };

        let keypair = match keypair {
            Some(location) => {
                let (peer_id, noise_keypair) = client
                    .derive_noise_keypair(location)
                    .map_err(|e| SpawnNetworkError::Inner(e.to_string()))?;

                Some(InitKeypair::Authenticated { peer_id, noise_keypair })
            }
            None => None,
        };

        // set inner network reference
        network.replace(Network::new(network_config, keypair).await?);

        Ok(())
    }
}

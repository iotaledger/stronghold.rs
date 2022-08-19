// Copyright 2020-202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1 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// p2p Stronghold functionality
#[cfg(feature = "p2p")]
mod p2p_old;

#[cfg(feature = "p2p")]
pub mod network_old;

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, RwLock, RwLockWriteGuard},
};

use crate::{
    procedures::Runner,
    sync::{SnapshotHierarchy, SyncSnapshots, SyncSnapshotsConfig},
    Client, ClientError, ClientState, KeyProvider, LoadFromPath, Location, RemoteMergeError, RemoteVaultError,
    Snapshot, SnapshotPath, Store, UseKey,
};

#[cfg(feature = "p2p")]
use crate::{Peer, SpawnNetworkError};

use crypto::keys::x25519;
use engine::vault::ClientId;
#[cfg(feature = "p2p")]
use futures::channel::mpsc::UnboundedSender;
#[cfg(feature = "p2p")]
use futures::channel::oneshot::Sender;

#[cfg(feature = "p2p")]
use futures::{future, SinkExt, StreamExt};

#[cfg(feature = "p2p")]
pub use p2p_old::*;

#[cfg(feature = "p2p")]
use stronghold_p2p::DialErr;
#[cfg(feature = "p2p")]
use stronghold_p2p::{
    identity::{Keypair, PublicKey},
    InitKeypair,
};
#[cfg(feature = "p2p")]
use stronghold_p2p::{Executor, ListenErr, Multiaddr, PeerId};

#[cfg(feature = "p2p")]
use futures::{channel::mpsc::UnboundedReceiver, future::Either};
use stronghold_utils::GuardDebug;

#[cfg(feature = "p2p")]
use crate::network_old::Network;

#[cfg(feature = "p2p")]
use self::network_old::StrongholdRequest;

#[cfg(feature = "p2p")]
use self::network_old::{ClientRequest, NetworkConfig, SnapshotRequest, StrongholdNetworkResult};

use std::ops::Deref;

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

    #[cfg(feature = "p2p")]
    network: Arc<futures::lock::Mutex<Option<Network>>>,

    #[cfg(feature = "p2p")]
    peers: Arc<futures::lock::Mutex<HashMap<PeerId, Peer>>>,
}

impl Stronghold {
    /// Drop all references
    ///
    /// # Example
    pub fn reset(self) -> Self {
        Self::default()
    }

    /// Load the state of a [`Snapshot`] at given `snapshot_path`.
    /// The [`Snapshot`] is secured in memory and may be used to load further
    /// clients with [`Stronghold::load_client`].
    /// Load a [`Client`] at `client_path` from the snapshot.
    ///
    /// # Example
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
    pub fn load_client<P>(&self, client_path: P) -> Result<Client, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());
        let mut client = Client::default();

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

    /// Writes all client states into the [`Snapshot`] file
    ///
    /// # Example
    pub fn commit(&self, snapshot_path: &SnapshotPath, keyprovider: &KeyProvider) -> Result<(), ClientError> {
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
        for (_, c) in self.clients.try_write()?.iter() {
            c.clear()?;
        }
        self.snapshot.try_write()?.clear()?;
        self.store.clear()?;

        Ok(())
    }
}

// networking functionality

/// This enum is solely used for steering the control flow
/// of a serving [`Stronghold`] instance
#[cfg(feature = "p2p")]
pub(crate) enum ServeCommand {
    /// Continue Serving
    Continue,

    /// Terminate Serving
    Terminate,
}

#[cfg(feature = "p2p")]
impl Stronghold {
    /// Processes [`ClientRequest`]s
    ///
    /// # Example
    pub(crate) fn handle_client_request<P>(
        &self,
        client_path: P,
        tx: Sender<StrongholdNetworkResult>,
        request: ClientRequest,
    ) -> Result<(), ClientError>
    where
        P: AsRef<[u8]>,
    {
        // load client
        let client = self.get_client(client_path).unwrap(); // get or load client?

        match request {
            network_old::ClientRequest::CheckVault { vault_path } => {
                let result = client.vault_exists(vault_path);

                tx.send(StrongholdNetworkResult::Bool(result.unwrap())).unwrap();
                Ok(())
            }
            network_old::ClientRequest::CheckRecord { location } => {
                let result = client.record_exists(&location);
                tx.send(StrongholdNetworkResult::Bool(result.unwrap())).unwrap();

                Ok(())
            }

            network_old::ClientRequest::WriteToRemoteVault { location, payload } => {
                let vault = client.vault(location.vault_path());
                let result = vault.write_secret(location, payload);

                tx.send(StrongholdNetworkResult::Empty(())).unwrap();
                Ok(())
            }

            network_old::ClientRequest::DeleteData { location } => {
                let vault = client.vault(location.vault_path());
                match vault.delete_secret(location.record_path()) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            network_old::ClientRequest::ReadFromStore { key } => {
                let store = client.store();
                let result = store.get(&key)?;
                tx.send(StrongholdNetworkResult::Data(result))
                    .map_err(|_| ClientError::Inner("Failed to send response".to_string()))?;
                Ok(())
            }
            network_old::ClientRequest::WriteToStore { key, payload, lifetime } => {
                let store = client.store();
                store.insert(key, payload, lifetime)?;

                tx.send(StrongholdNetworkResult::Empty(())).unwrap();
                Ok(())
            }
            network_old::ClientRequest::DeleteFromStore { key } => {
                let store = client.store();
                store.delete(&key)?;

                tx.send(StrongholdNetworkResult::Empty(())).unwrap();
                Ok(())
            }

            network_old::ClientRequest::Procedures { procedures } => {
                let result = client.execute_procedure_chained(procedures);
                assert!(result.is_ok());
                assert!(tx.send(StrongholdNetworkResult::Proc(result)).is_ok());

                Ok(())
            }

            // what is the difference to "WriteToRemoteVault" ?
            network_old::ClientRequest::WriteToVault { location, payload } => {
                let vault_path = location.vault_path();
                let vault = client.vault(vault_path);
                vault.write_secret(location, payload)?;
                tx.send(StrongholdNetworkResult::Empty(())).unwrap();

                Ok(())
            }
            network_old::ClientRequest::RevokeData { location } => {
                let record_path = location.record_path();
                let vault = client.vault(location.vault_path());
                vault.revoke_secret(record_path)?;

                tx.send(StrongholdNetworkResult::Empty(())).unwrap();

                Ok(())
            }
        }
    }

    /// Processes [`SnapshotRequest`]s
    ///
    /// # Example
    pub(crate) fn handle_snapshot_request(
        &self,
        // client_path: P,
        tx: Sender<StrongholdNetworkResult>,
        request: SnapshotRequest,
    ) -> Result<(), ClientError> {
        match request {
            SnapshotRequest::ExportRemoteDiff { dh_pub_key, diff } => {
                let snapshot = self.snapshot.try_read()?;

                let result = snapshot.export_to_serialized_state(diff, x25519::PublicKey::from_bytes(dh_pub_key));

                let result = match result {
                    Ok((public_key, encrypted)) => {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(public_key.as_slice());

                        Ok((encrypted, pk))
                    }
                    Err(e) => Err(RemoteMergeError::ReadExported(e.to_string())),
                };

                tx.send(StrongholdNetworkResult::Exported(result)).expect("msg");

                Ok(())
            }
            SnapshotRequest::GetRemoteHierarchy => {
                let snapshot = self.snapshot.try_read()?;
                let hierarchy = snapshot.get_hierarchy(Some(snapshot.clients()));

                let is_ok = hierarchy.is_ok();
                assert!(is_ok);

                // FIXME: the error mapping is wrong
                tx.send(StrongholdNetworkResult::Hierarchy(
                    // Ok(SnapshotHierarchy::default()),
                    hierarchy.map_err(|e| RemoteVaultError::Record(e.to_string())),
                ))
                .expect("Could not send request");
                Ok(())
            }
        }
    }

    /// Clears the currently available network
    pub async fn clear_network(&self) -> Result<(), ClientError> {
        let mut network = self.network.lock().await;

        if let Some(inner) = &*network {
            inner.stop_listening().await?;
        }

        *network = None;

        self.peers.lock().await.clear();

        Ok(())
    }

    /// Serve requests to remote Stronghold clients. This call is blocking.
    /// Accepts a receiver to terminate the listener.
    ///
    /// # Example
    pub async fn serve(&self, mut shutdown: UnboundedReceiver<()>) -> Result<(), ClientError> {
        use future::FutureExt;

        // FIXME: pull the [`network`]-type up
        let mut network = self.network.lock().await;
        let mut rx = network.as_mut().unwrap().inbound_request_rx.take().unwrap();
        drop(network);

        // we keep handling all requests in a busy loop, blocking on receiving requests while
        // being able to respond to termination requests.
        loop {
            match futures::future::select(
                Box::pin(async {
                    let _ = shutdown.next().await;
                    ServeCommand::Terminate
                }),
                Box::pin(async {
                    if let Some(inner) = rx.next().await {
                        // request handling comes here
                        match inner.request {
                            network_old::StrongholdRequest::ClientRequest { client_path, request } => {
                                if let Err(e) = self.handle_client_request(client_path, inner.response_tx, request) {
                                    // handle error. log it?
                                    println!("Encountered error handling client request {:?}", e);
                                }
                            }
                            network_old::StrongholdRequest::SnapshotRequest { request } => {
                                if let Err(e) = self.handle_snapshot_request(inner.response_tx, request) {
                                    // handle error. log it?
                                    println!("Encountered error handling snapshot request {:?}", e);
                                }
                            }
                        };
                    }
                    ServeCommand::Continue
                }),
            )
            .await
            {
                Either::Left((cmd, _)) | Either::Right((cmd, _)) => {
                    if let ServeCommand::Terminate = cmd {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Creates a [`Peer`] from a [`PublicKey`] and returns it.
    ///
    /// # Example
    pub async fn create_remote_client<P>(&self, public_key: PublicKey, client_path: P) -> Result<Peer, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let peer_id = public_key.to_peer_id();
        let mut peers = self.peers.lock().await;
        match peers.entry(peer_id) {
            Entry::Occupied(o) => Ok(o.get().clone()),
            Entry::Vacant(v) => {
                let peer = Peer::new(*v.key(), client_path, self.clone());
                v.insert(peer.clone());
                Ok(peer)
            }
        }
    }

    /// Creates a new empty [`Client`] with an identity [`Keypair`] stored at [`Location`]
    ///
    /// # Example
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
    /// (either via `Client::generate_p2p_keypair` or `Client::write_p2p_keypair`).
    /// A new noise `AuthenticKeypair` and the [`PeerId`] will be derived from this keypair and used
    /// for authentication and encryption on the transport layer.
    ///
    /// **Note**: The noise keypair differs for each derivation, the [`PeerId`] is consistent.
    ///
    /// # Example
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

    /// Adds a [`Multiaddr`] for a peer, represented by the [`PeerId`]
    ///
    /// # Example
    pub async fn add_peer_addr(&self, peer: PeerId, address: Multiaddr) -> Result<Multiaddr, DialErr> {
        let network = self.network.lock().await;
        let network = match &*network {
            Some(network) => network,
            None => return Err(DialErr::NoAddresses),
        };

        network.add_peer_address(peer, address.clone()).await.map(|_| address)
    }

    /// Tries to connect to a remote Peer, if the peer is already known by [`Multiaddr`] or
    /// mDNS. If the peer is not know, try to add it first via [`Self::add_peer_addr`].
    ///
    /// # Example
    pub async fn connect(&self, peer: PeerId) -> Result<(), DialErr> {
        let network = self.network.lock().await;
        let network = match &*network {
            Some(network) => network,
            None => return Err(DialErr::Aborted),
        };

        network.connect_peer(peer).await.map(|_| ()) // returned Multiadress
    }

    /// Sends a request to an already connected remote Peer.
    /// TBD: THIS NEEDS MORE EXPLANATION
    ///
    /// # Example
    pub async fn send<P, R>(
        &self,
        peer_id: PeerId,
        client_path: P,
        request: R,
    ) -> Result<StrongholdNetworkResult, ClientError>
    where
        P: AsRef<[u8]>,
        R: Into<StrongholdRequest>,
    {
        // FIXME: this call just passes through to network. The abstraction is
        // just one more layer of redundancy.
        let network = self.network.lock().await;
        let network = match &*network {
            Some(network) => network,
            None => {
                return Err(ClientError::NoValuePresent(
                    "inner network reference not present".to_string(),
                ))
            }
        };

        network.send_request(peer_id, /* client_path, */ request.into()).await
    }

    // TODO: experimental api
    // pub async fn send_request<P, R>(
    //     &self,
    //     peer_id: Option<PeerId>,
    //     client_path: P,
    //     request: R,
    // ) -> Result<R::Response, ClientError>
    // where
    //     P: AsRef<[u8]>,
    //     R: Request,
    // {
    //     // // FIXME: this call just passes through to network. The abstraction is
    //     // // just one more layer of redundancy.
    //     // let network = self.network.lock().await;
    //     // let network = match &*network {
    //     //     Some(network) => network,
    //     //     None => {
    //     //         return Err(ClientError::NoValuePresent(
    //     //             "inner network reference not present".to_string(),
    //     //         ))
    //     //     }
    //     // };

    //     // network.send_request(peer_id, client_path, request.into()).await
    //     todo!()
    // }

    // // FIXME: experimental api
    // impl_request_handler!(handle_check_vault, (self, request, client_path, tx), {
    //     let CheckVault { vault_path, counter } = *request.inner().downcast()?;

    //     // load client
    //     let client = self.get_client(client_path)?;
    //     tx.send(client.vault_exists(vault_path)?).unwrap();

    //     Ok(())
    // });
}

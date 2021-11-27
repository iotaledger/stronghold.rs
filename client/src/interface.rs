// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Main Stronghold Interface
//!
//! All functionality can be accessed from the interface. Functions
//! are provided in an asynchronous way, and should be run by the
//! actor's system [`SystemRunner`].

#[cfg(feature = "p2p")]
use crate::procedures::FatalProcedureError;
use crate::{
    actors::{
        secure_messages::{
            CheckRecord, CheckVault, ClearCache, DeleteFromStore, GarbageCollect, GetData, ListIds, ReadFromStore,
            ReloadData, RevokeData, WriteToStore, WriteToVault,
        },
        snapshot_messages::{ActorStateFromSnapshot, FillSnapshot, LoadFromDisk, WriteSnapshot},
        GetAllClients, GetClient, GetSnapshot, GetTarget, RecordError, Registry, Registry2, RemoveClient,
        SetAllClients, SpawnClient, SwitchTarget,
    },
    procedures::{CollectedOutput, Procedure, ProcedureError},
    state::{
        secure::SecureClient,
        snapshot::{ReadError, Snapshot, SnapshotFile, WriteError},
    },
    utils::{LoadFromPath, StrongholdFlags, VaultFlags},
    Location,
};
use engine::vault::{ClientId, RecordHint, RecordId};
#[cfg(feature = "p2p")]
use p2p::{identity::Keypair, DialErr, InitKeypair, ListenErr, ListenRelayErr, OutboundFailure, RelayNotSupported};

use actix::{prelude::*, WeakAddr};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use thiserror::Error as DeriveError;
use zeroize::Zeroize;

#[cfg(test)]
use crate::actors::secure_testing::ReadFromVault;

#[cfg(feature = "p2p")]
use crate::actors::{
    client_p2p_messages::{DeriveNoiseKeypair, GenerateP2pKeypair, WriteP2pKeypair},
    network_messages,
    network_messages::{ShRequest, SwarmInfo},
    GetNetwork, InsertNetwork, NetworkActor, NetworkConfig, RemoveNetwork,
};
#[cfg(feature = "p2p")]
use p2p::{
    firewall::{Rule, RuleDirection},
    Multiaddr, PeerId,
};
#[cfg(feature = "p2p")]
use std::io;

pub type StrongholdResult<T> = Result<T, ActorError>;

#[derive(DeriveError, Debug)]
pub enum ActorError {
    #[error("actor mailbox error: {0}")]
    Mailbox(#[from] MailboxError),
    #[error("target actor has not been spawned or was killed")]
    TargetNotFound,
}

#[cfg(feature = "p2p")]
pub type P2pResult<T> = Result<T, P2pError>;

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug)]
pub enum P2pError {
    #[error("local actor error: {0}")]
    Local(#[from] ActorError),
    #[error("sending request to remote stronghold failed: {0}")]
    SendRequest(#[from] OutboundFailure),
}

#[cfg(feature = "p2p")]
impl From<MailboxError> for P2pError {
    fn from(e: MailboxError) -> Self {
        P2pError::Local(e.into())
    }
}

#[cfg(feature = "p2p")]
#[derive(DeriveError, Debug)]
pub enum SpawnNetworkError {
    #[error("actor mailbox error: {0}")]
    ActorMailbox(#[from] MailboxError),

    #[error("network already running")]
    AlreadySpawned,

    #[error("no client found for loading the config")]
    ClientNotFound,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Error loading network config: {0}")]
    LoadConfig(String),

    #[error("Error deriving noise-keypair: {0}")]
    DeriveKeypair(String),
}

#[cfg(feature = "p2p")]
impl From<ActorError> for SpawnNetworkError {
    fn from(e: ActorError) -> Self {
        match e {
            ActorError::Mailbox(e) => SpawnNetworkError::ActorMailbox(e),
            ActorError::TargetNotFound => SpawnNetworkError::ClientNotFound,
        }
    }
}

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
#[error("fatal engine error: {0}")]
pub struct FatalEngineError(String);

impl From<RecordError> for FatalEngineError {
    fn from(e: RecordError) -> Self {
        FatalEngineError(e.to_string())
    }
}

impl From<String> for FatalEngineError {
    fn from(e: String) -> Self {
        FatalEngineError(e)
    }
}

#[derive(Clone)]
/// The main type for the Stronghold System.  Used as the entry point for the actor model.  Contains various pieces of
/// metadata to interpret the data in the vault and store.
pub struct Stronghold {
    registry: Addr<Registry>,
}

impl Stronghold {
    /// Initializes a new instance of the system asynchronously.  Sets up the first client actor. Accepts
    /// the first client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
    /// The [`actix::SystemRunner`] is not being used directly by stronghold, and must be initialized externally.
    pub async fn init_stronghold_system(
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StrongholdResult<Self> {
        // Init actor registry.
        let registry = Registry::default().start();

        // create client actor
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        registry.send(SpawnClient { id: client_id }).await?;

        Ok(Self { registry })
    }

    /// Spawn a new client for the Stronghold system and switch the actor target to it.
    /// Accepts the client_path: [`Vec<u8>`] and the options: `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone());
        self.registry.send(SpawnClient { id: client_id }).await?;
        Ok(())
    }

    /// Switches the actor target to another actor in the system specified by the client_path: [`Vec<u8>`].
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path, &client_path);
        self.switch_client(client_id).await.map(|_| ())
    }

    /// Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified
    /// location of [`Location`] type. The payload must be specified as a [`Vec<u8>`] and a [`RecordHint`] can be
    /// provided. Also accepts [`VaultFlags`] for when a new Vault is created.
    pub async fn write_to_vault(
        &self,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let target = self.target().await?;
        // write to vault
        let res = target
            .send(WriteToVault {
                location,
                payload,
                hint,
            })
            .await?
            .map_err(FatalEngineError::from);
        Ok(res)
    }

    /// Writes data into an insecure cache.  This method, accepts a [`Vec<u8>`] as key, a [`Vec<u8>`] payload, and an
    /// optional [`Duration`]. The lifetime allows the data to be deleted after the specified duration has passed.
    /// If no lifetime is specified, the data will persist until it is manually deleted or over-written.
    /// Returns [`None`] if the key didn't exist yet. If the key is already present, the value is updated, and the old
    /// value is returned.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn write_to_store(
        &self,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let existing = target.send(WriteToStore { key, payload, lifetime }).await?;
        Ok(existing)
    }

    /// A method that reads from an insecure cache. This method, accepts a [`Vec<u8>`] as key and returns the payload
    /// in the form of a ([`Vec<u8>`].  If the key does not exist, `None` is returned.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn read_from_store(&self, key: Vec<u8>) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let data = target.send(ReadFromStore { key }).await?;
        Ok(data)
    }

    /// A method to delete data from an insecure cache. This method, accepts a [`Vec<u8>`] as key.
    ///
    /// Note: One store is mapped to one client. The same key can be specified across multiple clients.
    pub async fn delete_from_store(&self, key: Vec<u8>) -> StrongholdResult<()> {
        let target = self.target().await?;
        target.send(DeleteFromStore { key }).await?;
        Ok(())
    }

    /// Revokes the data from the specified location of type [`Location`]. Revoked data is not readable and can be
    /// removed from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call
    /// with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(
        &self,
        location: Location,
        should_gc: bool,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let target = self.target().await?;
        let res = target
            .send(RevokeData {
                location: location.clone(),
            })
            .await?;
        match res {
            Ok(_) => {}
            Err(e) => return Ok(Err(FatalEngineError::from(e))),
        };

        if should_gc {
            target.send(GarbageCollect { location }).await?;
        }
        Ok(Ok(()))
    }

    /// Garbage collects any revokes in a Vault based on the given `vault_path` and the current target actor.
    ///
    /// Return `false` if the vault does not exist.
    pub async fn garbage_collect<V: Into<Vec<u8>>>(&self, vault_path: V) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let vault_exists = target
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path: vault_path.into(),
                    record_path: Vec::new(),
                },
            })
            .await?;
        Ok(vault_exists)
    }

    /// Returns a list of the available [`RecordId`] and [`RecordHint`] values in a vault by the given `vault_path`.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> StrongholdResult<Vec<(RecordId, RecordHint)>> {
        let target = self.target().await?;
        let list = target
            .send(ListIds {
                vault_path: vault_path.into(),
            })
            .await?;
        Ok(list)
    }

    /// Executes a runtime command given a [`Procedure`].
    pub async fn runtime_exec<P>(&self, control_request: P) -> StrongholdResult<Result<CollectedOutput, ProcedureError>>
    where
        P: Into<Procedure>,
    {
        let target = self.target().await?;
        let result = target.send::<Procedure>(control_request.into()).await?;
        Ok(result)
    }

    /// Checks whether a record exists in the client based off of the given [`Location`].
    pub async fn record_exists(&self, location: Location) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let exists = target.send(CheckRecord { location }).await?;
        Ok(exists)
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists<V: Into<Vec<u8>>>(&self, vault_path: V) -> StrongholdResult<bool> {
        let target = self.target().await?;
        let exists = target
            .send(CheckVault {
                vault_path: vault_path.into(),
            })
            .await?;
        Ok(exists)
    }

    /// Reads data from a given snapshot file.  Can only read the data for a single `client_path` at a time. If the new
    /// actor uses a new `client_path` the former client path may be passed into the function call to read the data into
    /// that actor. Also requires keydata to unlock the snapshot. A filename and filepath can be specified. The Keydata
    /// should implement and use Zeroize.
    pub async fn read_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        _client_path: Vec<u8>,
        _former_client_path: Option<Vec<u8>>,
        _keydata: &T,
        _filename: Option<String>,
        _path: Option<PathBuf>,
    ) -> StrongholdResult<Result<(), ReadError>> {
        unimplemented!();
    }

    /// Writes the entire state of the [`Stronghold`] into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        _keydata: &T,
        _filename: Option<String>,
        _path: Option<PathBuf>,
    ) -> StrongholdResult<Result<(), WriteError>> {
        unimplemented!()
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true`, the actor will be removed from the system.  Otherwise, the cache of the
    /// current target actor will be cleared.
    ///
    /// **Note**: If `kill_actor` is set to `true` and the target is the currently active client, a new client has to be
    /// set via [`Stronghold::switch_actor_target`], before any following operations can be performed.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StrongholdResult<()> {
        let client_id = ClientId::load_from_path(&client_path.clone(), &client_path);
        let client;
        if kill_actor {
            client = self
                .registry
                .send(RemoveClient { id: client_id })
                .await?
                .ok_or(ActorError::TargetNotFound)?;
        } else {
            client = self
                .registry
                .send(GetClient { id: client_id })
                .await?
                .ok_or(ActorError::TargetNotFound)?;
        }
        client.send(ClearCache).await?;
        Ok(())
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    // API CHANGE!
    #[cfg(test)]
    pub async fn read_secret(&self, _client_path: Vec<u8>, location: Location) -> StrongholdResult<Option<Vec<u8>>> {
        let target = self.target().await?;
        let secret = target.send(ReadFromVault { location }).await?;
        Ok(secret)
    }

    async fn switch_client(&mut self, client_id: ClientId) -> StrongholdResult<Addr<SecureClient>> {
        self.registry
            .send(SwitchTarget { id: client_id })
            .await?
            .ok_or(ActorError::TargetNotFound)
    }

    async fn target(&self) -> StrongholdResult<Addr<SecureClient>> {
        self.registry.send(GetTarget).await?.ok_or(ActorError::TargetNotFound)
    }
}

/// Represents the in-memory version of an encrypted snapshot file. The [`Vault`] can be used to
/// securely store key material and operate on said material. An unencrypted HashMap-like [`Store`]
/// can be used to store miscellaneous data.
// Note: This is no longer `Clone`, because `write_snapshot`
// needs to operate on the stronghold in a mutually exclusive manner.
pub struct Stronghold2 {
    registry: Addr<Registry2>,
}

impl Stronghold2 {
    /// Initializes a new Stronghold.
    pub fn new() -> Self {
        let registry = Registry2::default().start();

        Self { registry }
    }

    /// Returns the [`Client`] identified by `client_path`.
    ///
    /// A client has a corresponding actix actor that is either reused if it exists,
    /// or newly spawned. This method can be called with the same `client_path` multiple
    /// times to get the same client. Alternatively, the returned client can be cloned.
    pub async fn client<C: AsRef<[u8]>>(&self, client_path: &C) -> StrongholdResult<Client> {
        let client_id = ClientId::load_from_path(client_path.as_ref(), client_path.as_ref());

        let get_client = self.registry.send(GetClient { id: client_id }).await?;

        let secure_client = match get_client {
            Some(secure_client) => Ok(secure_client),
            None => self.registry.send(SpawnClient { id: client_id }).await,
        }?;

        let snapshot_actor = self.registry.send(GetSnapshot {}).await?;

        Ok(Client::new(client_id, secure_client, snapshot_actor))
    }

    /// Loads the snapshot from disk identified by TODO. The given `key_data` is used to
    /// attempt decryption of the file. After this method is called, `key_data` should be zeroized.
    // TODO: Can we take owned key_data and zeroize ourselves?
    pub async fn read_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        key_data: &T,
        snapshot_file: SnapshotFile,
    ) -> StrongholdResult<Result<(), ReadError>> {
        let mut key: [u8; 32] = [0u8; 32];
        let keydata = key_data.as_ref();

        key.copy_from_slice(keydata);

        let snapshot_actor = self.registry.send(GetSnapshot {}).await?;

        let result = snapshot_actor.send(LoadFromDisk { key, snapshot_file }).await?;

        if let Err(e) = result {
            return Ok(Err(e));
        }

        Ok(Ok(()))
    }

    pub async fn write_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        snapshot_file: SnapshotFile,
    ) -> StrongholdResult<Result<(), WriteError>> {
        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();
        key.copy_from_slice(keydata);

        let clients: Vec<(ClientId, Addr<SecureClient>)> = self.registry.send(GetAllClients).await?;
        let snapshot = self.registry.send(GetSnapshot {}).await?;

        for (id, client) in clients.iter() {
            let data = client.send(GetData {}).await?;

            snapshot.send(FillSnapshot { data, id: *id }).await?;
        }

        let weak_addrs: Vec<(ClientId, WeakAddr<SecureClient>)> =
            clients.into_iter().map(|(id, addr)| (id, addr.downgrade())).collect();

        let previous_len = weak_addrs.len();

        // Don't short-circuit, as that would get rid of all clients.
        let res = snapshot.send(WriteSnapshot { key, snapshot_file }).await;

        // It's important that the actor task/thread gets a chance to run, in order to
        // drop the actors whose references have now gone away.
        // A yield_now (tokio or thread) seems to already be good enough.
        // Here, putting the `WriteSnapshot` in between is more than good enough.
        let clients: Vec<(ClientId, Addr<SecureClient>)> = weak_addrs
            .into_iter()
            .filter_map(|(id, addr)| {
                if let Some(addr) = addr.upgrade() {
                    Some((id, addr))
                } else {
                    None
                }
            })
            .collect();

        println!("[write_snapshot] removed {} clients", previous_len - clients.len());

        self.registry.send(SetAllClients(clients)).await?;

        Ok(res?)
    }
}

/// A client is a wrapper around a stronghold actor that can be obtained through [`Stronghold2::client`].
/// A client can be cloned and used from different tasks or threads.
#[derive(Clone)]
pub struct Client {
    id: ClientId,
    secure_client: Addr<SecureClient>,
    snapshot_actor: Addr<Snapshot>,
}

impl Client {
    fn new(id: ClientId, secure_client: Addr<SecureClient>, snapshot_actor: Addr<Snapshot>) -> Client {
        Client {
            id,
            secure_client,
            snapshot_actor,
        }
    }

    /// Returns the underlying actor.
    fn actor(&self) -> &Addr<SecureClient> {
        &self.secure_client
    }

    pub async fn restore_state(&self) -> StrongholdResult<()> {
        let content = self.snapshot_actor.send(ActorStateFromSnapshot { id: self.id }).await?;

        self.actor()
            .send(ReloadData {
                data: content.data,
                id: content.id,
            })
            .await?;

        Ok(())
    }

    /// Saves the client's state into the stronghold in-memory snapshot.
    pub async fn save_state(&self) -> StrongholdResult<()> {
        let data = self.secure_client.send(GetData {}).await?;
        // self.secure_client.do_send(msg)
        self.snapshot_actor.send(FillSnapshot { data, id: self.id }).await?;

        Ok(())
    }

    pub fn vault<V: Into<Vec<u8>>>(&self, vault_path: V) -> Vault {
        Vault::new(self, vault_path.into())
    }

    pub fn store(&self) -> Store {
        Store::new(self)
    }

    // Should this live in `Vault`?
    pub async fn execute_procedure<P>(
        &self,
        control_request: P,
    ) -> StrongholdResult<Result<CollectedOutput, ProcedureError>>
    where
        P: Into<Procedure>,
    {
        let result = self.secure_client.send::<Procedure>(control_request.into()).await?;
        Ok(result)
    }
}

pub struct Store<'client> {
    client: &'client Client,
}

impl<'client> Store<'client> {
    fn new(client: &'client Client) -> Self {
        Self { client }
    }

    pub async fn write(
        &self,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StrongholdResult<Option<Vec<u8>>> {
        let existing = self
            .client
            .actor()
            .send(WriteToStore { key, payload, lifetime })
            .await?;
        Ok(existing)
    }

    pub async fn read(&self, key: Vec<u8>) -> StrongholdResult<Option<Vec<u8>>> {
        let data = self.client.actor().send(ReadFromStore { key }).await?;
        Ok(data)
    }

    pub async fn delete(&self, key: Vec<u8>) -> StrongholdResult<()> {
        self.client.actor().send(DeleteFromStore { key }).await?;
        Ok(())
    }
}

pub struct Vault<'client> {
    vault_path: Vec<u8>,
    client: &'client Client,
}

impl<'client> Vault<'client> {
    fn new(client: &'client Client, vault_path: Vec<u8>) -> Self {
        Self { vault_path, client }
    }

    pub async fn write(
        &self,
        vault_location: VaultLocation,
        payload: Vec<u8>,
        hint: RecordHint,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let res = self
            .client
            .actor()
            .send(WriteToVault {
                location: vault_location.into_location(self.vault_path.clone()),
                payload,
                hint,
            })
            .await?
            .map_err(FatalEngineError::from);

        Ok(res)
    }

    pub async fn revoke(
        &self,
        vault_location: VaultLocation,
        collect_garbage: bool,
    ) -> StrongholdResult<Result<(), FatalEngineError>> {
        let location: Location = vault_location.into_location(self.vault_path.clone());
        let res = self
            .client
            .actor()
            .send(RevokeData {
                location: location.clone(),
            })
            .await?;
        match res {
            Ok(_) => {}
            Err(e) => return Ok(Err(FatalEngineError::from(e))),
        };

        if collect_garbage {
            self.client.actor().send(GarbageCollect { location }).await?;
        }

        Ok(Ok(()))
    }

    pub async fn collect_garbage(&self) -> StrongholdResult<bool> {
        let vault_exists = self
            .client
            .actor()
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path: self.vault_path.clone(),
                    record_path: Vec::new(),
                },
            })
            .await?;
        Ok(vault_exists)
    }

    pub async fn exists(&self) -> StrongholdResult<bool> {
        let exists = self
            .client
            .actor()
            .send(CheckVault {
                vault_path: self.vault_path.clone(),
            })
            .await?;
        Ok(exists)
    }

    // TODO: Is this useful for users? Should this be behind #[cfg(test)]?
    pub async fn list(&self) -> StrongholdResult<Vec<(RecordId, RecordHint)>> {
        let list = self
            .client
            .actor()
            .send(ListIds {
                vault_path: self.vault_path.clone(),
            })
            .await?;
        Ok(list)
    }

    #[cfg(test)]
    pub async fn read_secret(&self, location: VaultLocation) -> StrongholdResult<Option<Vec<u8>>> {
        let secret = self
            .client
            .actor()
            .send(ReadFromVault {
                location: location.into_location(self.vault_path.clone()),
            })
            .await?;
        Ok(secret)
    }
}

#[derive(Debug, Clone)]
pub enum VaultLocation {
    Generic(Vec<u8>),
    Counter(usize),
}

impl VaultLocation {
    pub fn generic<V: Into<Vec<u8>>>(record_path: V) -> Self {
        Self::Generic(record_path.into())
    }

    pub const fn counter(counter: usize) -> Self {
        Self::Counter(counter)
    }

    pub fn into_location(self, vault_path: Vec<u8>) -> Location {
        match self {
            VaultLocation::Generic(name) => Location::generic(vault_path, name),
            VaultLocation::Counter(counter) => Location::counter(vault_path, counter),
        }
    }
}

#[cfg(feature = "p2p")]
impl Stronghold {
    /// Spawn the p2p-network actor and swarm.
    /// The `keypair`parameter can be provided as location in which a keypair is stored,
    /// (either via [`Stronghold::generate_p2p_keypair`] or [`Stronghold::write_p2p_keypair`]).
    /// A new noise [`AuthenticKeypair`] and the [`PeerId`] will be derived from this keypair and used
    /// for authentication and encryption on the transport layer.
    ///
    /// **Note**: The noise keypair differs for each derivation, the [`PeerId`] is consistent.
    pub async fn spawn_p2p(
        &mut self,
        network_config: NetworkConfig,
        keypair: Option<Location>,
    ) -> Result<(), SpawnNetworkError> {
        if self.registry.send(GetNetwork).await?.is_some() {
            return Err(SpawnNetworkError::AlreadySpawned);
        }
        let keypair = match keypair {
            Some(location) => {
                let target = self.target().await?;
                let (peer_id, noise_keypair) = target
                    .send(DeriveNoiseKeypair { p2p_keypair: location })
                    .await?
                    .map_err(|e| SpawnNetworkError::DeriveKeypair(e.to_string()))?;
                Some(InitKeypair::Authenticated { peer_id, noise_keypair })
            }
            None => None,
        };
        let addr = NetworkActor::new(self.registry.clone(), network_config, keypair)
            .await?
            .start();
        self.registry.send(InsertNetwork { addr }).await?;
        Ok(())
    }

    /// Spawn the p2p-network actor and swarm, load the config from a former running network-actor.
    /// The `key` parameter species the location in which in the config is stored, i.g.
    /// the key that was set on [`Stronghold::stop_p2p`].
    ///
    /// **Note**: Firewall rules with [`Rule::Restricted`] can not be serialized / deserialized, hence
    /// they will be skipped and have to be added manually.
    pub async fn spawn_p2p_load_config(
        &mut self,
        key: Vec<u8>,
        keypair: Option<Location>,
    ) -> Result<(), SpawnNetworkError> {
        let config_bytes = self
            .read_from_store(key.clone())
            .await?
            .ok_or_else(|| SpawnNetworkError::LoadConfig(format!("No config found at key {:?}", key)))?;
        let config = bincode::deserialize(&config_bytes)
            .map_err(|e| SpawnNetworkError::LoadConfig(format!("Deserializing state failed: {}", e.to_string())))?;
        self.spawn_p2p(config, keypair).await
    }

    /// Generate a new p2p-keypair in the vault.
    /// This keypair can be used with [`Stronghold::spawn_p2p`] and [`Stronghold::spawn_p2p_load_config`] to derive a
    /// new noise-keypair and peer id for encryption and authentication on the p2p transport layer.
    pub async fn generate_p2p_keypair(
        &mut self,
        location: Location,
        hint: RecordHint,
    ) -> StrongholdResult<Result<(), FatalProcedureError>> {
        let target = self.target().await?;
        let res = target
            .send(GenerateP2pKeypair { location, hint })
            .await?
            .map_err(|e| e.to_string().into());
        Ok(res)
    }

    /// Write an existing [`Keypair`] into the vault.
    /// This keypair can then be used with [`Stronghold::spawn_p2p`] and [`Stronghold::spawn_p2p_load_config`] to derive
    /// a new noise-keypair and peer id for encryption and authentication on the p2p transport layer.
    pub async fn write_p2p_keypair(
        &mut self,
        keypair: Keypair,
        location: Location,
        hint: RecordHint,
    ) -> StrongholdResult<Result<(), FatalProcedureError>> {
        let target = self.target().await?;
        let res = target
            .send(WriteP2pKeypair {
                keypair,
                location,
                hint,
            })
            .await?
            .map_err(|e| e.to_string().into());
        Ok(res)
    }

    /// Gracefully stop the network actor and swarm.
    /// Return `false` if there is no active network actor.
    /// Optionally store the current config (known addresses of remote peers and firewall rules) in the store
    /// at the specified `key`.
    ///
    /// **Note**: Firewall rules with [`Rule::Restricted`] can not be serialized / deserialized, hence
    /// they will be skipped and have to be added manually again after init.
    pub async fn stop_p2p(&mut self, write_config: Option<Vec<u8>>) -> StrongholdResult<bincode::Result<()>> {
        let actor = self
            .registry
            .send(RemoveNetwork)
            .await?
            .ok_or(ActorError::TargetNotFound)?;
        if let Some(key) = write_config {
            let config = actor.send(network_messages::ExportConfig).await?;
            let payload = match bincode::serialize(&config) {
                Ok(bytes) => bytes,
                Err(e) => return Ok(Err(e)),
            };
            self.write_to_store(key, payload, None).await?;
        }
        Ok(Ok(()))
    }

    // Export the config and state of the p2p-layer.
    pub async fn export_config(&mut self) -> StrongholdResult<NetworkConfig> {
        let actor = self.network_actor().await?;
        let config = actor.send(network_messages::ExportConfig).await?;
        Ok(config)
    }

    /// Start listening on the swarm to the given address. If not address is provided, it will be assigned by the OS.
    pub async fn start_listening(&self, address: Option<Multiaddr>) -> StrongholdResult<Result<Multiaddr, ListenErr>> {
        let actor = self.network_actor().await?;
        let result = actor.send(network_messages::StartListening { address }).await?;
        Ok(result)
    }

    /// Stop listening on the swarm.
    pub async fn stop_listening(&self) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_messages::StopListening).await?;
        Ok(())
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(&self) -> StrongholdResult<SwarmInfo> {
        let actor = self.network_actor().await?;
        let info = actor.send(network_messages::GetSwarmInfo).await?;
        Ok(info)
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by the address if one is provided, or by peer id
    /// if the peer is already known e.g. from multicast DNS.
    /// If the peer is not a relay and can not be reached directly, it will be attempted to reach it via the relays,
    /// if there are any.
    pub async fn add_peer(
        &self,
        peer: PeerId,
        address: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Multiaddr, DialErr>> {
        let actor = self.network_actor().await?;
        if let Some(address) = address {
            actor.send(network_messages::AddPeerAddr { peer, address }).await?;
        }
        let result = actor.send(network_messages::ConnectPeer { peer }).await?;
        Ok(result)
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub async fn add_dialing_relay(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Option<Multiaddr>, RelayNotSupported>> {
        let actor = self.network_actor().await?;
        let result = actor
            .send(network_messages::AddDialingRelay { relay, relay_addr })
            .await?;
        Ok(result)
    }

    /// Start listening via a relay peer on an address following the scheme
    /// `<relay-addr>/<relay-id>/p2p-circuit/<local-id>`. This will establish a keep-alive connection to the relay,
    /// the relay will forward all requests to the local peer.
    pub async fn start_relayed_listening(
        &self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
    ) -> StrongholdResult<Result<Multiaddr, ListenRelayErr>> {
        let actor = self.network_actor().await?;
        let result = actor
            .send(network_messages::StartListeningRelay { relay, relay_addr })
            .await?;
        Ok(result)
    }

    /// Stop listening with the relay.
    pub async fn remove_listening_relay(&self, relay: PeerId) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_messages::StopListeningRelay { relay }).await?;
        Ok(())
    }

    /// Remove a peer from the list of peers used for dialing.
    pub async fn remove_dialing_relay(&self, relay: PeerId) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        actor.send(network_messages::RemoveDialingRelay { relay }).await?;
        Ok(())
    }

    /// Change the firewall rule for specific peers, optionally also set it as the default rule, which applies if there
    /// are no specific rules for a peer. All inbound requests from the peers that this rule applies to, will be
    /// approved/ rejected based on this rule.
    pub async fn set_firewall_rule(
        &self,
        rule: Rule<ShRequest>,
        peers: Vec<PeerId>,
        set_default: bool,
    ) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;

        if set_default {
            actor
                .send(network_messages::SetFirewallDefault {
                    direction: RuleDirection::Inbound,
                    rule: rule.clone(),
                })
                .await?;
        }

        for peer in peers {
            actor
                .send(network_messages::SetFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                    rule: rule.clone(),
                })
                .await?;
        }
        Ok(())
    }

    /// Remove peer specific rules from the firewall configuration.
    pub async fn remove_firewall_rules(&self, peers: Vec<PeerId>) -> StrongholdResult<()> {
        let actor = self.network_actor().await?;
        for peer in peers {
            actor
                .send(network_messages::RemoveFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                })
                .await?;
        }
        Ok(())
    }

    /// Write to the vault of a remote Stronghold.
    pub async fn write_remote_vault(
        &self,
        peer: PeerId,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> P2pResult<Result<(), FatalEngineError>> {
        let actor = self.network_actor().await?;

        // write data
        let send_request = network_messages::SendRequest {
            peer,
            request: network_messages::WriteToRemoteVault {
                location: location.clone(),
                payload: payload.clone(),
                hint,
            },
        };
        let res = actor.send(send_request).await??.map_err(FatalEngineError::from);
        Ok(res)
    }

    /// Write to the store of a remote Stronghold.
    ///
    /// Returns [`None`] if the key didn't exist yet. If the key is already present, the value is updated, and the old
    /// value is returned.
    pub async fn write_to_remote_store(
        &self,
        peer: PeerId,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> P2pResult<Option<Vec<u8>>> {
        let actor = self.network_actor().await?;
        let send_request = network_messages::SendRequest {
            peer,
            request: WriteToStore { key, payload, lifetime },
        };
        let existing = actor.send(send_request).await??;
        Ok(existing)
    }

    /// Read from the store of a remote Stronghold.
    pub async fn read_from_remote_store(&self, peer: PeerId, key: Vec<u8>) -> P2pResult<Option<Vec<u8>>> {
        let actor = self.network_actor().await?;
        let send_request = network_messages::SendRequest {
            peer,
            request: ReadFromStore { key },
        };
        let data = actor.send(send_request).await??;
        Ok(data)
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer: PeerId,
        vault_path: V,
    ) -> P2pResult<Vec<(RecordId, RecordHint)>> {
        let actor = self.network_actor().await?;
        let send_request = network_messages::SendRequest {
            peer,
            request: ListIds {
                vault_path: vault_path.into(),
            },
        };
        let list = actor.send(send_request).await??;
        Ok(list)
    }

    /// Executes a runtime command at a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn remote_runtime_exec<P>(
        &self,
        peer: PeerId,
        control_request: P,
    ) -> P2pResult<Result<CollectedOutput, ProcedureError>>
    where
        P: Into<Procedure>,
    {
        let actor = self.network_actor().await?;
        let send_request = network_messages::SendRequest::<Procedure> {
            peer,
            request: control_request.into(),
        };
        let result = actor.send(send_request).await??;
        Ok(result)
    }

    async fn network_actor(&self) -> StrongholdResult<Addr<NetworkActor>> {
        self.registry.send(GetNetwork).await?.ok_or(ActorError::TargetNotFound)
    }
}

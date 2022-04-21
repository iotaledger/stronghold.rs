// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use super::{location, snapshot};

#[cfg(feature = "p2p")]
use crate::network_old::{SnapshotRequest, StrongholdNetworkResult, StrongholdRequest};
use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    sync::{KeyProvider, MergePolicy, SyncClients, SyncClientsConfig, SyncSnapshots, SyncSnapshotsConfig},
    ClientError, ClientState, ClientVault, KeyStore, Location, Provider, RecordError, SnapshotError, Store, Stronghold,
};
use crypto::keys::x25519;
use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{view::Record, BoxProvider, ClientId, DbView, Id, Key, RecordHint, RecordId, VaultId},
};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};
#[cfg(feature = "p2p")]
use stronghold_p2p::DialErr;
use stronghold_utils::GuardDebug;
use zeroize::Zeroize;

#[cfg(feature = "p2p")]
use stronghold_p2p::{identity::Keypair, AuthenticKeypair, NoiseKeypair, PeerId};

#[derive(Clone, GuardDebug)]
pub struct Client {
    // A keystore
    pub(crate) keystore: Arc<RwLock<KeyStore<Provider>>>,

    // A view on the vault entries
    pub(crate) db: Arc<RwLock<DbView<Provider>>>,

    // The id of this client
    pub id: ClientId,

    // Contains the Record Ids for the most recent Record in each vault.
    pub store: Store,

    #[cfg(feature = "p2p")]
    pub(crate) peer_id: PeerId,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            keystore: Arc::new(RwLock::new(KeyStore::default())),
            db: Arc::new(RwLock::new(DbView::new())),
            id: ClientId::default(),
            store: Store::default(),

            #[cfg(feature = "p2p")]
            peer_id: PeerId::random(),
        }
    }
}

impl Client {
    /// Returns an atomic reference to the [`Store`]
    ///
    /// # Example
    /// ```
    /// ```
    pub fn store(&self) -> Store {
        self.store.clone()
    }

    /// Returns a [`Vault`] according to path
    ///
    /// # Example
    /// ```
    /// ```
    pub fn vault<P>(&self, vault_path: P) -> ClientVault
    where
        P: AsRef<[u8]>,
    {
        ClientVault {
            client: self.clone(),
            vault_path: vault_path.as_ref().to_vec(),
        }
    }

    /// Returns `true`, if a vault exists
    ///
    /// # Example
    /// ```
    /// ```
    pub fn vault_exists<P>(&self, vault_path: P) -> Result<bool, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let vault_id = derive_vault_id(vault_path);
        let keystore = self.keystore.try_read()?;

        Ok(keystore.vault_exists(vault_id))
    }

    /// Returns Ok(true), if the record exsist. Ok(false), if not. An error is being
    /// returned, if inner database could not be unlocked.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn record_exists(&self, location: &Location) -> Result<bool, ClientError> {
        let (vault_id, record_id) = location.resolve();
        let db = self.db.try_read()?;
        let contains_record = db.contains_record(vault_id, record_id);
        Ok(contains_record)
    }

    /// Synchronize two vaults of the client so that records are copied from `source` to `target`.
    /// If `select_records` is `Some` only the specified records are copied, else a full sync
    /// is performed. If a record already exists at the target, the [`MergePolicy`] applies.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn sync_vaults(
        &self,
        source_path: Vec<u8>,
        target_path: Vec<u8>,
        select_records: Option<Vec<RecordId>>,
        merge_policy: MergePolicy,
    ) -> Result<(), ClientError> {
        let source = derive_vault_id(source_path);
        let target = derive_vault_id(target_path);
        let select_vaults = vec![source];
        let map_vaults = [(source, target)].into();
        let select_records = select_records.map(|vec| [(source, vec)].into()).unwrap_or_default();
        let mut config = SyncClientsConfig {
            select_vaults: Some(select_vaults),
            select_records,
            map_vaults,
            merge_policy,
        };
        let hierarchy = self.get_hierarchy(config.select_vaults.clone())?;
        let diff = self.get_diff(hierarchy, &config)?;
        let exported = self.export_entries(diff)?;
        let mut db = self.db.try_write()?;
        let mut key_store = self.keystore.try_write()?;

        for (vid, records) in exported {
            let mapped_vid = config.map_vaults.remove(&vid).unwrap_or(vid);
            let old_key = key_store
                .get_key(vid)
                .ok_or_else(|| ClientError::Inner(format!("Missing Key for vault {:?}", vid)))?;
            let new_key = key_store.get_or_insert_key(mapped_vid, Key::random())?;
            db.import_records(&old_key, &new_key, mapped_vid, records)?
        }
        Ok(())
    }

    /// Synchronize the client with another one so that records are copied from `other` to `self`.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn sync_with(&self, other: &Self, config: SyncClientsConfig) -> Result<(), ClientError> {
        let hierarchy = other.get_hierarchy(config.select_vaults.clone())?;
        let diff = self.get_diff(hierarchy, &config)?;
        let exported = other.export_entries(diff)?;

        for (vid, mut records) in exported {
            if let Some(select_vaults) = config.select_vaults.as_ref() {
                if !select_vaults.contains(&vid) {
                    continue;
                }
            }
            if let Some(select_records) = config.select_records.get(&vid) {
                records.retain(|(rid, _)| select_records.contains(rid));
            }
            let mapped_vid = config.map_vaults.get(&vid).copied().unwrap_or(vid);
            let old_key = other
                .keystore
                .try_read()?
                .get_key(vid)
                .ok_or_else(|| ClientError::Inner(format!("Missing Key for vault {:?}", vid)))?;
            let new_key = self
                .keystore
                .try_write()?
                .get_or_insert_key(mapped_vid, Key::random())?;
            self.db
                .try_write()?
                .import_records(&old_key, &new_key, mapped_vid, records)?
        }
        Ok(())
    }

    /// Returns the [`ClientId`] of the client
    ///
    /// # Example
    /// ```
    /// ```
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Loads the state of [`Self`] from a [`ClientState`]. Replaces all previous data.
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn restore(&self, state: ClientState, id: ClientId) -> Result<(), ClientError> {
        let (keys, db, st) = state;

        // reload keystore
        let mut keystore = self.keystore.try_write()?;
        let mut new_keystore = KeyStore::<Provider>::default();
        new_keystore
            .rebuild_keystore(keys)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        *keystore = new_keystore;
        drop(keystore);

        // reload db
        let mut view = self.db.try_write()?;
        *view = db;
        drop(view);

        // reload store
        let mut store = self.store.cache.try_write()?;
        *store = st;
        drop(store);

        Ok(())
    }

    /// Executes a cryptographic [`Procedure`] and returns its output.
    /// A cryptographic [`Procedure`] is the main operation on secrets.
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub fn execute_procedure<P>(&self, procedure: P) -> Result<P::Output, ProcedureError>
    where
        P: Procedure + Into<StrongholdProcedure>,
    {
        let res = self.execure_procedure_chained(vec![procedure.into()]);
        let mapped = res.map(|mut vec| vec.pop().unwrap().try_into().ok().unwrap())?;
        Ok(mapped)
    }

    /// Executes a list of cryptographic [`Procedures`] sequentially and returns a collected output
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub fn execure_procedure_chained(
        &self,
        procedures: Vec<StrongholdProcedure>,
    ) -> core::result::Result<Vec<ProcedureOutput>, ProcedureError> {
        let mut out = Vec::new();
        let mut log = Vec::new();
        // Execute the procedures sequentially.
        for proc in procedures {
            if let Some(output) = proc.output() {
                log.push(output);
            }
            let output = match proc.execute(self) {
                Ok(o) => o,
                Err(e) => {
                    for location in log {
                        let _ = self.revoke_data(&location);
                    }
                    return Err(e);
                }
            };
            out.push(output);
        }
        Ok(out)
    }
}

impl<'a> SyncClients<'a> for Client {
    type Db = RwLockReadGuard<'a, DbView<Provider>>;

    fn get_db(&'a self) -> Result<Self::Db, ClientError> {
        let db = self.db.try_read()?;
        Ok(db)
    }

    fn get_key_provider(&'a self) -> Result<KeyProvider<'a>, ClientError> {
        let ks = self.keystore.try_read()?;
        Ok(KeyProvider::KeyStore(ks))
    }
}

#[cfg(feature = "p2p")]
impl Client {
    /// This generates a new [`Keypair`] and stores it in a [`Location`]. The new
    /// keypair will be used for Stronghold's networking capability
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn generate_p2p_keypair(&self, location: Location) -> Result<(), ClientError> {
        self.write_p2p_keypair(Keypair::generate_ed25519(), location)
    }

    /// Writes an existing [`Keypair`] into [`Location`]
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn write_p2p_keypair(&self, keypair: Keypair, location: Location) -> Result<(), ClientError> {
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        let vault = self.vault(location.vault_path());
        vault.write_secret(location, bytes)?;

        Ok(())
    }

    /// Derive a new noise keypair from a stored p2p-keypair.
    /// Returns the new keypair and the `PeerId` that is derived from the public
    /// key of the stored keypair.
    ///
    /// ## Note
    /// The keypair differs for each new derivation, the `PeerId` is consistent.
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn derive_noise_keypair(&self, location: Location) -> Result<(PeerId, AuthenticKeypair), ClientError> {
        let mut id_keys = None;
        let f = |guard: Buffer<u8>| {
            let keys = Keypair::from_protobuf_encoding(&*guard.borrow()).map_err(|e| e.to_string())?;
            let _ = id_keys.insert(keys);
            Ok(())
        };
        self.get_guard(&location, f)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        let id_keys = id_keys.unwrap();
        let keypair = NoiseKeypair::new()
            .into_authentic(&id_keys)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        let peer_id = PeerId::from_public_key(&id_keys.public());
        Ok((peer_id, keypair))
    }
}

/// [`Peer`] represents a remote [`Client`]. It contains no inner state, and its
/// sole purpose is to work with remotes
#[cfg(feature = "p2p")]
#[derive(Clone, GuardDebug)]
pub struct Peer {
    /// the id of the remote peer
    peer_id: Arc<PeerId>,

    /// reference to networking
    stronghold: Stronghold,
    // The remote client path
    // Is this necessary?
    remote_client_path: Arc<Vec<u8>>,
}

#[cfg(feature = "p2p")]
impl Peer {
    /// Creates a new [`Peer`] from a [`PeerId`] and a reference to [`Stronghold`] for p2p functionality
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn new<P>(peer_id: PeerId, remote_client_path: P, stronghold: Stronghold) -> Self
    where
        P: AsRef<[u8]>,
    {
        Peer {
            peer_id: peer_id.into(),
            stronghold,
            remote_client_path: Arc::new(remote_client_path.as_ref().to_vec()),
        }
    }

    /// Connects to a remote [`Stronghold`] instance
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn connect(&self) -> Result<(), DialErr> {
        self.stronghold.connect(*self.peer_id).await
    }

    /// Executes a procedure on the remote
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_procedure_exec(
        &self,
        procedure: StrongholdProcedure,
    ) -> Result<StrongholdNetworkResult, ClientError> {
        self.remote_procedure_exec_chained(vec![procedure]).await
    }

    /// Executes sequential procedures on the remote.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_procedure_exec_chained(
        &self,
        procedures: Vec<StrongholdProcedure>,
    ) -> Result<StrongholdNetworkResult, ClientError> {
        let client_path = (*self.remote_client_path).clone();

        let result = self
            .stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::Procedures { procedures },
                },
            )
            .await;

        result
    }

    /// Checks, if a remote vault exists and returns
    /// - Ok(true), if the vault exists
    /// - Ok(false), if the vault does not exist
    ///  
    /// # Example
    /// ```
    /// ```
    pub async fn remote_vault_exists<P>(&self, vault_path: P) -> Result<bool, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_path = (*self.remote_client_path).clone();
        let vault_path = vault_path.as_ref().to_vec();

        let result = self
            .stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::CheckVault {
                        vault_path: vault_path.clone(),
                    },
                },
            )
            .await;

        match result {
            Ok(inner) => match inner {
                StrongholdNetworkResult::Bool(b) => Ok(b),
                _ => Err(ClientError::Inner(
                    "Unexpected data type returned from request".to_string(),
                )),
            },
            Err(_) => Err(ClientError::NoValuePresent(format!(
                "Vault at path ({:?}) does not exist. ",
                vault_path
            ))),
        }
    }

    /// Checks, if a remote record exists and returns
    /// - Ok(true), if the record exists
    /// - Ok(false), if the record does not exist
    ///  
    /// # Example
    /// ```
    /// ```
    pub async fn remote_record_exists<P>(&self, vault_path: P, record_path: P) -> Result<bool, ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client_path = (*self.remote_client_path).clone();
        let location = Location::generic(vault_path.as_ref().clone(), record_path.as_ref().clone());

        let result = self
            .stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::CheckRecord { location },
                },
            )
            .await;

        match result {
            Ok(inner) => match inner {
                StrongholdNetworkResult::Bool(b) => Ok(b),
                _ => Err(ClientError::Inner(
                    "Unexpected data type returned from request".to_string(),
                )),
            },
            Err(_) => Err(ClientError::NoValuePresent(format!(
                "Record at path ({:?}) does not exist. ",
                record_path.as_ref()
            ))),
        }
    }

    /// Synchronizes local entries with a remote instance. Giving config, what entries
    /// need to be sychronized. This involves an diffie-helmann key exchange.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_sync(&self, config: SyncSnapshotsConfig) -> Result<(), ClientError> {
        let mut ephemeral = [0u8; x25519::SECRET_KEY_LENGTH];
        crypto::utils::rand::fill(&mut ephemeral).expect("Could not fill ephemeral key");
        let ephemeral_key = x25519::SecretKey::from_bytes(ephemeral);

        let mut ephemeral_public_key_bytes = [0u8; x25519::PUBLIC_KEY_LENGTH];
        ephemeral_public_key_bytes.copy_from_slice(ephemeral_key.public_key().as_slice());

        let mut vault_path = [0u8; 24];
        crypto::utils::rand::fill(&mut vault_path).expect("Could not fill random vault_path");

        let mut record_path = [0u8; 24];
        crypto::utils::rand::fill(&mut record_path).expect("Could not fill random record_path");

        let random_key_location = Location::const_generic(vault_path.to_vec(), record_path.to_vec());

        // get remote hierarchy
        let result = self
            .stronghold
            .send(
                *self.peer_id,
                (*self.remote_client_path).clone(),
                StrongholdRequest::SnapshotRequest {
                    request: SnapshotRequest::GetRemoteHierarchy,
                },
            )
            .await?;

        // unwrap remote hierarchy
        let hierarchy = match result {
            StrongholdNetworkResult::Hierarchy(inner) => inner,
            _ => return Err(ClientError::Inner("Unknown Return type".to_owned())),
        };

        // get snapshot and write ephemeral key
        let mut snapshot = self.stronghold.get_snapshot()?;
        let vault_id = VaultId::load(&vault_path).unwrap();
        let record_id = RecordId::load(&record_path).unwrap();
        snapshot
            .store_secret_key(ephemeral, vault_id, record_id)
            .expect("Could not store ephemeral key");

        // calculate diff from local snapshot with remote hiearchy
        let diff = snapshot
            .get_diff(hierarchy.unwrap(), &config)
            .expect("Failed to get diff");

        // send diff to remote Stronghold instance to export snapshot and retrieve
        // the encrypted snapshot
        let result = self
            .stronghold
            .send(
                *self.peer_id,
                (*self.remote_client_path).clone(),
                StrongholdRequest::SnapshotRequest {
                    request: SnapshotRequest::ExportRemoteDiff {
                        dh_pub_key: ephemeral_public_key_bytes,
                        diff,
                    },
                },
            )
            .await?;

        // extract exported and encrypted snapshot data
        let (exported, remote_public_key_bytes) = match result {
            StrongholdNetworkResult::Exported(inner) => {
                let (exported, remote_public_key_bytes) = inner.expect("Export of remote snapshot failed");
                (exported, remote_public_key_bytes)
            }
            _ => return Err(ClientError::Inner("Getting remote snapshot export failed".to_string())),
        };

        let remote_public_key = x25519::PublicKey::from_bytes(remote_public_key_bytes);

        // import encrypted snapshot data to our own
        snapshot
            .import_from_serialized_state(exported, random_key_location, remote_public_key, config)
            .expect("Could not import serialized state");

        Ok(())
    }

    /// Write to remote store
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_write_store(
        &self,
        key: Vec<u8>,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> Result<StrongholdNetworkResult, ClientError> {
        let client_path = (*self.remote_client_path).clone();

        self.stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::WriteToStore { key, payload, lifetime },
                },
            )
            .await
    }

    /// Read from remote store and return an optional result.
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_read_store<P>(&self, key: P) -> Result<StrongholdNetworkResult, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_path = (*self.remote_client_path).clone();

        self.stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::ReadFromStore {
                        key: key.as_ref().to_vec(),
                    },
                },
            )
            .await
    }

    /// Removes an entry from the remote ['Store`].
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_delete_store<P>(&self, key: P) -> Result<StrongholdNetworkResult, ClientError>
    where
        P: AsRef<[u8]>,
    {
        let client_path = (*self.remote_client_path).clone();

        self.stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::DeleteFromStore {
                        key: key.as_ref().to_vec(),
                    },
                },
            )
            .await
    }

    /// Writes secret data in the remote vault
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_write_secret<P>(
        &self,
        vault_path: P,
        record_path: P,
        payload: Vec<u8>,
    ) -> Result<(), ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client_path = (*self.remote_client_path).clone();
        let location = Location::const_generic(vault_path.as_ref().to_vec(), record_path.as_ref().to_vec());

        self.stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::WriteToVault { location, payload },
                },
            )
            .await
            .map(|_| ())
    }

    /// Removes a secret from a remote [`Stronghold`]
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn remote_remove_secret<P>(&self, vault_path: P, record_path: P) -> Result<(), ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let client_path = (*self.remote_client_path).clone();
        let location = Location::const_generic(vault_path.as_ref().to_vec(), record_path.as_ref().to_vec());

        self.stronghold
            .send(
                *self.peer_id,
                client_path.clone(),
                StrongholdRequest::ClientRequest {
                    client_path,
                    request: crate::network_old::ClientRequest::RevokeData { location },
                },
            )
            .await
            .map(|_| ())
    }
}

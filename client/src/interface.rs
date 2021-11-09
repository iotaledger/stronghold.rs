// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Main Stronghold Interface
//!
//! All functionality can be accessed from the interface. Functions
//! are provided in an asynchronous way, and should be run by the
//! actor's system [`SystemRunner`].

use actix::prelude::*;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use zeroize::Zeroize;

use crate::{
    actors::{
        secure_messages::{
            CheckRecord, CheckVault, ClearCache, CreateVault, DeleteFromStore, GarbageCollect, GetData, ListIds,
            ReadFromStore, ReloadData, RevokeData, WriteToStore, WriteToVault,
        },
        secure_procedures::{CallProcedure, ProcResult, Procedure},
        snapshot_messages::{
            CalculateComplement, CalculateShape, ExportAllEntries, ExportSnapshot, FillSnapshot, FullSynchronization,
            ImportSnapshot, PartialSynchronization, ReadFromSnapshot, WriteSnapshot,
        },
        GetAllClients, GetClient, GetSnapshot, GetTarget, Registry, RegistryError, RemoveClient, SecureClient,
        SnapshotConfig, SpawnClient, SwitchTarget,
    },
    line_error,
    state::snapshot::SnapshotError,
    utils::{EntryShape, LoadFromPath, ResultMessage, StatusMessage, StrongholdFlags, VaultFlags},
    Location,
};
use engine::vault::{ClientId, RecordHint, RecordId};

#[cfg(feature = "p2p")]
use crate::{
    actors::{
        p2p::{
            messages as network_msg,
            messages::{ShRequest, SwarmInfo},
            NetworkActor, NetworkConfig,
        },
        GetNetwork, InsertNetwork, StopNetwork,
    },
    unwrap_or_err, unwrap_result_msg,
};
#[cfg(feature = "p2p")]
use p2p::{
    firewall::{Rule, RuleDirection},
    Multiaddr, PeerId,
};

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
    ) -> Result<Self, anyhow::Error> {
        // create client actor
        let client_id = ClientId::load_from_path(&client_path, &client_path)
            .unwrap_or_else(|_| panic!("{}", crate::Error::IDError));

        // the registry will be run as a system service
        let registry = Registry::default().start();

        // we need to block for the target client actor
        match registry.send(SpawnClient { id: client_id }).await? {
            Ok(addr) => addr,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };

        Ok(Self { registry })
    }

    /// Spawn a new client for the Stronghold system and switch the actor target to it.
    /// Accepts the client_path: [`Vec<u8>`] and the options: `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());
        if let Err(e) = self.registry.send(SpawnClient { id: client_id }).await {
            return StatusMessage::Error(format!("Could spawn new client: {:?}", e));
        }
        match self.switch_client(client_id).await {
            ResultMessage::Ok(_) => StatusMessage::OK,
            ResultMessage::Error(e) => StatusMessage::Error(e),
        }
    }

    /// Switches the actor target to another actor in the system specified by the client_path: [`Vec<u8>`].
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());
        match self.switch_client(client_id).await {
            ResultMessage::Ok(_) => StatusMessage::OK,
            ResultMessage::Error(e) => StatusMessage::Error(e),
        }
    }

    async fn switch_client(&mut self, client_id: ClientId) -> ResultMessage<Addr<SecureClient>> {
        match self.registry.send(SwitchTarget { id: client_id }).await {
            Ok(Ok(addr)) => ResultMessage::Ok(addr),
            Ok(Err(e)) => ResultMessage::Error(format!("Could not switch target for network actor: {:?}", e)),
            Err(e) => ResultMessage::Error(format!("Could not switch target for network actor: {:?}", e)),
        }
    }

    /// Partially synchronizes this stronghold instance snapshot with another, eventually writes the synchronized
    /// snapshot to disk. After the operation, the current state will be optionally resumed.
    ///
    /// TODO
    /// we need to handle four cases here:
    /// 1. local full synchronization
    /// 2. local partial synchronization
    /// 3. remote full synchronization
    /// 4. remote partial sychronization
    ///
    /// 1 + 2 are a trivial implementation of comparing two snapshots according to their client paths ( extension to
    /// fine-grained control over records is possible). while 3 + 4 need some extra layer of security to not expose
    /// secrets, even though they might be encrypted.
    pub async fn synchronize_partial(
        &self,
        id: ClientId,
        source: SnapshotConfig,
        sync_with: SnapshotConfig,
        destination: SnapshotConfig,
        allowed: Vec<ClientId>,
    ) -> ResultMessage<()> {
        let snapshot_actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return ResultMessage::Error(error.to_string()),
        };

        let result = match snapshot_actor
            .send(PartialSynchronization {
                allowed,
                source,
                compare: sync_with,
                destination,
                id,
            })
            .await
            .unwrap()
        {
            Ok(result) => result,
            Err(e) => return ResultMessage::Error(e.to_string()),
        };

        // load the current target
        if let Some(target) = match self.registry.send(GetTarget {}).await {
            Ok(current) => current,
            Err(error) => return ResultMessage::Error(error.to_string()),
        } {
            // send data to secure actor and reload
            return match target
                .send(ReloadData {
                    data: result.data,
                    id: result.id,
                })
                .await
            {
                Ok(_) => ResultMessage::Ok(()),
                Err(e) => ResultMessage::Error(e.to_string()),
            };
        }

        ResultMessage::Error(RegistryError::NoClientPresentById(format!("{:?}", id)).to_string())
    }

    /// Fully synchronizes the current snapshot state with another snapshot, write the result eventually to disk.
    pub async fn synchronize_full(
        &self,
        id: ClientId,
        source: SnapshotConfig,
        sync_with: SnapshotConfig,
        destination: SnapshotConfig,
    ) -> ResultMessage<()> {
        let snapshot_actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return ResultMessage::Error(error.to_string()),
        };

        let result = match snapshot_actor
            .send(FullSynchronization {
                source,
                merge: sync_with,
                destination,
                id,
            })
            .await
            .unwrap()
        {
            Ok(result) => result,
            Err(error) => return ResultMessage::Error(error.to_string()),
        };

        // load the current target
        if let Some(target) = match self.registry.send(GetTarget {}).await {
            Ok(current) => current,
            Err(error) => return ResultMessage::Error(error.to_string()),
        } {
            // send data to secure actor and reload
            return match target
                .send(ReloadData {
                    data: result.data,
                    id: result.id,
                })
                .await
            {
                Ok(_) => ResultMessage::Ok(()),
                Err(e) => ResultMessage::Error(e.to_string()),
            };
        }

        ResultMessage::Error(RegistryError::NoClientPresentById(format!("{:?}", id)).to_string())
    }

    // /// Exports selected entries from the current state
    // pub async fn synchronize_with_remote(&self) {
    //     // accept the locations to be exported, alongside the old and new keys
    // }

    // pub async fn synchronized_from_remote(&self) {
    //     // accept
    // }

    /// Exports all locations across all [`ClientId`]s from their respective vaults.
    pub(crate) async fn snapshot_protocol_export_shapes(
        &self,
        entries: Vec<Location>,
    ) -> Result<HashMap<Location, EntryShape>, SnapshotError> {
        // CalculateComplement, CalculateShape, ExportAllEntries, ExportSnapshot
        // get the snapshot actor
        let actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        // get export data
        let _data = match actor.send(ExportAllEntries { entries }).await {
            Ok(result) => match result {
                Ok(result) => result,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        // calculate shape
        // TODO: set data
        match actor
            .send(CalculateShape {
                entries: None,
                // data: None,
                hasher: None,
            })
            .await
        {
            Ok(shapes) => shapes,
            Err(error) => Err(SnapshotError::ExportError(error.to_string())),
        }
    }

    /// Calculates the complement set for B (receiver) from A (sender). The complement set
    /// consists of all parts that are missing inside B and should be send from A.
    pub(crate) async fn snapshot_protocol_calculate_complement(
        &self,
        input: HashMap<Location, EntryShape>,
    ) -> Result<Vec<Location>, SnapshotError> {
        // get the snapshot actor
        let actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        let complement = match actor.send(CalculateComplement { input }).await {
            Ok(result) => match result {
                Ok(entries) => entries,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        Ok(complement)
    }

    pub(crate) async fn snapshot_protocol_export_snapshot(
        &self,
        input: Vec<Location>,
        public_key: Vec<u8>,
        client_id: ClientId,
    ) -> Result<Vec<u8>, SnapshotError> {
        // get the snapshot actor
        let actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        // export the snapshot
        let snapshot = match actor
            .send(ExportSnapshot {
                input,
                public_key,
                client_id,
            })
            .await
        {
            Ok(result) => match result {
                Ok(snapshot) => snapshot,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        Ok(snapshot)
    }

    /// Imports the snapshot from bytes into the current actor
    pub(crate) async fn snapshot_protocol_import_snapshot<K>(
        &self,
        input: Vec<u8>,
        key_data: &K,

        _id: ClientId,
    ) -> Result<(), SnapshotError>
    where
        K: Zeroize + AsRef<Vec<u8>>,
    {
        // get the snapshot actor
        let actor = match self.registry.send(GetSnapshot {}).await {
            Ok(actor) => actor,
            Err(error) => return Err(SnapshotError::ExportError(error.to_string())),
        };

        // create key
        let mut key = [0u8; 32];
        key.copy_from_slice(key_data.as_ref());

        // import the snapshot
        if let Err(error) = actor.send(ImportSnapshot { input, key }).await {
            return Err(SnapshotError::ImportFailure(error.to_string()));
        };

        // // get target actor
        // let target = match self.registry.send(GetTarget {}).await {
        //     Ok(target) => target,
        //     Err(error) => return Err(SnapshotError::OtherFailure(error.to_string())),
        // };

        // reload snapshot

        // merge with current state
        // self.synchronize_full(id, source, sync_with, destination);

        // // unwrapping the target might induce an error
        // match target.unwrap().send(ReloadData { data, id }).await {
        //     Ok(_) => {}
        //     Err(_) => {}
        // };

        // match target
        //     .send(ImportData {
        //         data: result.data,
        //         id: result.id,
        //     })
        //     .await
        // {
        //     Ok(_) => StatusMessage::OK,
        //     Err(e) => StatusMessage::Error(format!("Error requestion Reload Data: {}", e)),
        // }

        // this may be remove
        Ok(())
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
    ) -> StatusMessage {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };

        if let Ok(vault_exists) = target.send(CheckVault { vault_path }).await {
            if vault_exists {
                // exists
                return match target
                    .send(WriteToVault {
                        location,
                        payload,
                        hint,
                    })
                    .await
                {
                    Ok(result) => match result {
                        Ok(_) => StatusMessage::OK,
                        Err(e) => StatusMessage::Error(e.to_string()),
                    },
                    Err(e) => StatusMessage::Error(e.to_string()),
                };
            } else {
                // does not exist
                match target
                    .send(CreateVault {
                        location: location.clone(),
                    })
                    .await
                {
                    Ok(_) => {
                        // write to vault
                        if let Ok(result) = target
                            .send(WriteToVault {
                                location,
                                payload,
                                hint,
                            })
                            .await
                        {
                            if result.is_ok() {
                                return StatusMessage::OK;
                            } else {
                                return StatusMessage::Error(result.err().unwrap().to_string());
                            }
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        }
                    }
                    Err(_e) => {
                        return StatusMessage::Error("Cannot create new vault".into());
                    }
                }
            }
        }

        StatusMessage::Error("Failed to write the data".into())
    }

    /// Writes data into an insecure cache.  This method, accepts a [`Location`], a [`Vec<u8>`] and an optional
    /// [`Duration`]. The lifetime allows the data to be deleted after the specified duration has passed.  If no
    /// lifetime is specified, the data will persist until it is manually deleted or over-written. Note: One store
    /// is mapped to one client. Can specify the same location across multiple clients.
    pub async fn write_to_store(
        &self,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };
        match target
            .send(WriteToStore {
                location,
                payload,
                lifetime,
            })
            .await
        {
            Ok(status) => status.into(),
            Err(_e) => StatusMessage::Error("Failed to write to the store".into()),
        }
    }

    /// A method that reads from an insecure cache.  This method, accepts a [`Location`] and returns the payload in the
    /// form of a ([`Vec<u8>`], [`StatusMessage`]).  If the location does not exist, an empty vector will be returned
    /// along with an error [`StatusMessage`].  Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn read_from_store(&self, location: Location) -> (Vec<u8>, StatusMessage) {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return (Vec::new(), ResultMessage::Error("No active client.".into())),
        };
        match target.send(ReadFromStore { location }).await {
            Ok(result) => match result {
                Ok(data) => (data, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
        }
    }

    /// A method to delete data from an insecure cache. This method, accepts a [`Location`] and returns a
    /// [`StatusMessage`]. Note: One store is mapped to one client. Can specify the same location across multiple
    /// clients.
    pub async fn delete_from_store(&self, location: Location) -> StatusMessage {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };
        match target.send(DeleteFromStore { location }).await {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(_e) => StatusMessage::Error("Failed to delete from the store".into()),
        }
    }

    /// Revokes the data from the specified location of type [`Location`]. Revoked data is not readable and can be
    /// removed from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call
    /// with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(&self, location: Location, should_gc: bool) -> StatusMessage {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };
        match target
            .send(RevokeData {
                location: location.clone(),
            })
            .await
        {
            Ok(result) => match result {
                Ok(_ok) if should_gc => match target.send(GarbageCollect { location }).await {
                    Ok(result) => match result {
                        Ok(_) => StatusMessage::OK,
                        Err(e) => StatusMessage::Error(format!("{:?}", e)),
                    },
                    Err(_e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
                },
                Ok(_ok) => StatusMessage::OK,
                Err(_e) => StatusMessage::Error("Could not revoke data".into()),
            },
            Err(_e) => StatusMessage::Error("Could not revoke data".into()),
        }
    }

    /// Garbage collects any revokes in a Vault based on the given `vault_path` and the current target actor.
    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };
        match target
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path,
                    record_path: Vec::new(),
                },
            })
            .await
        {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(_e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
        }
    }

    /// Returns a list of the available [`RecordId`] and [`RecordHint`] values in a vault by the given `vault_path`.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> (Vec<(RecordId, RecordHint)>, StatusMessage) {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return (Vec::new(), ResultMessage::Error("No active client.".into())),
        };
        match target
            .send(ListIds {
                vault_path: vault_path.into(),
            })
            .await
        {
            Ok(success) => match success {
                Ok(result) => (result, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(_e) => (
                Vec::new(),
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            ),
        }
    }

    /// Executes a runtime command given a [`Procedure`].  Returns a [`ProcResult`] based off of the control_request
    /// specified.
    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ProcResult::Error("No active client.".into()),
        };
        match target.send(CallProcedure { proc: control_request }).await {
            Ok(success) => match success {
                Ok(result) => result,
                Err(e) => ProcResult::Error(format!("{}", e)),
            },
            Err(e) => ProcResult::Error(format!("{}", e)),
        }
    }

    /// Checks whether a record exists in the client based off of the given [`Location`].
    pub async fn record_exists(&self, location: Location) -> bool {
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return false,
        };
        match target.send(CheckRecord { location }).await {
            Ok(result) => result,
            Err(_e) => false,
        }
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists(&self, location: Location) -> bool {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return false,
        };
        target.send(CheckVault { vault_path }).await.unwrap_or(false)
    }

    /// Reads data from a given snapshot file.  Can only read the data for a single `client_path` at a time. If the new
    /// actor uses a new `client_path` the former client path may be passed into the function call to read the data into
    /// that actor. Also requires keydata to unlock the snapshot. A filename and filepath can be specified. The Keydata
    /// should implement and use Zeroize.
    pub async fn read_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        client_path: Vec<u8>,
        former_client_path: Option<Vec<u8>>,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path).expect(line_error!());
        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return ResultMessage::Error("No active client.".into()),
        };

        // this feature resembles the functionality given by the former riker
        // system dependence. if there is a former client id path present,
        // the new actor is being changed into the former one ( see old ReloadData impl.)
        if let Some(path) = former_client_path.clone() {
            self.switch_actor_target(path).await;
        }

        let former_client_id = former_client_path.map(|cp| ClientId::load_from_path(&cp, &cp).unwrap());
        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        // get address of snapshot actor
        let snapshot_actor = match self.registry.send(GetSnapshot {}).await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                return StatusMessage::Error(format!("{}", e));
            }
        };

        // read the snapshots contents
        let result = match snapshot_actor
            .send(ReadFromSnapshot {
                key,
                filename,
                path,
                id: client_id,
                fid: former_client_id,
            })
            .await
        {
            Ok(result) => match result {
                Ok(result) => result,
                Err(e) => return StatusMessage::Error(format!("{}", e)),
            },
            Err(e) => return StatusMessage::Error(format!("{}", e)),
        };

        // send data to secure actor and reload
        match target
            .send(ReloadData {
                data: result.data,
                id: result.id,
            })
            .await
        {
            Ok(_) => StatusMessage::OK,
            Err(e) => StatusMessage::Error(format!("Error requestion Reload Data: {}", e)),
        }
    }

    /// Writes the entire state of the [`Stronghold`] into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        // this should be delegated to the secure client actor
        // wrapping the interior functionality inside it.
        let clients: Vec<(ClientId, Addr<SecureClient>)> = match self.registry.send(GetAllClients).await {
            Ok(clients) => clients,
            Err(_e) => {
                return StatusMessage::Error("Error retrieving SecureClientActors".into());
            }
        };

        let mut key: [u8; 32] = [0u8; 32];
        let keydata = keydata.as_ref();
        key.copy_from_slice(keydata);

        // get snapshot actor
        let snapshot = match self.registry.send(GetSnapshot {}).await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                return StatusMessage::Error(format!("{}", e));
            }
        };

        for (id, client) in clients {
            // get data from secure actor
            let data = match client.send(GetData {}).await {
                Ok(success) => match success {
                    Ok(data) => data,
                    Err(_) => {
                        return StatusMessage::Error("No Data present".into());
                    }
                },

                Err(_) => {
                    return StatusMessage::Error("Error communicating with client actor".into());
                }
            };

            // fill into snapshot
            if let Err(_e) = snapshot.send(FillSnapshot { data, id }).await {
                return StatusMessage::Error("Error filling data for snapshot".into());
            }
        } // end loop

        // write snapshot
        return match snapshot.send(WriteSnapshot { key, filename, path }).await {
            Ok(success) => match success {
                Err(e) => StatusMessage::Error(format!("{}", e)),
                _ => StatusMessage::OK,
            },
            Err(e) => StatusMessage::Error(format!("{}", e)),
        };
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true`, the actor will be removed from the system.  Otherwise, the cache of the
    /// current target actor will be cleared.
    ///
    /// **Note**: If `kill_actor` is set to `true` and the target is the currently active client, a new client has to be
    /// set via [`Stronghold::switch_actor_target`], before any following operations can be performed.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path.clone(), &client_path).expect(line_error!());
        if kill_actor {
            match self.registry.send(RemoveClient { id: client_id }).await {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{}", e)),
            }
        } else {
            let client = match self.registry.send(GetClient { id: client_id }).await.unwrap() {
                Some(addr) => addr,
                None => return StatusMessage::Error(format!("No client with id {:?}", client_id)),
            };

            match client.send(ClearCache).await {
                Ok(success) => match success {
                    Ok(_) => StatusMessage::OK,
                    Err(e) => StatusMessage::Error(format!("Cache clearing failed: {}", e)),
                },
                Err(e) => StatusMessage::Error(format!("{}", e)),
            }
        }
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    // API CHANGE!
    #[cfg(test)]
    pub async fn read_secret(&self, _client_path: Vec<u8>, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        use crate::actors::ReadFromVault;
        let empty_response = Some(Vec::new());

        let target = match self.registry.send(GetTarget).await.unwrap() {
            Some(addr) => addr,
            None => return (empty_response, ResultMessage::Error("No active client.".into())),
        };

        match target.send(ReadFromVault { location }).await {
            Ok(result) => match result {
                Ok(payload) => (Some(payload), StatusMessage::OK),
                Err(_e) => (empty_response, StatusMessage::Error("No payload present".into())),
            },
            Err(_e) => (empty_response, StatusMessage::Error("No secret present".into())),
        }
    }
}

#[cfg(feature = "p2p")]
impl Stronghold {
    /// Spawn the p2p-network actor and swarm.
    pub async fn spawn_p2p(&mut self, firewall_rule: Rule<ShRequest>, network_config: NetworkConfig) -> StatusMessage {
        let addr = match NetworkActor::new(self.registry.clone(), firewall_rule, network_config).await {
            Ok(actor) => actor.start(),
            Err(_) => return StatusMessage::Error("Spawning Network actor failed".into()),
        };
        match self.registry.send(InsertNetwork { addr }).await {
            Ok(()) => StatusMessage::OK,
            Err(_) => StatusMessage::Error("Spawning Network actor failed".into()),
        }
    }

    /// Gracefully stop the network actor and swarm.
    pub async fn stop_p2p(&mut self) {
        self.registry.send(StopNetwork).await.unwrap();
    }

    /// Start listening on the swarm to the given address. If not address is provided, it will be assigned by the OS.
    pub async fn start_listening(&self, address: Option<Multiaddr>) -> ResultMessage<Multiaddr> {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let res = actor.send(network_msg::StartListening { address }).await;
        let addr = unwrap_result_msg!(res);
        ResultMessage::Ok(addr)
    }

    /// Stop listening on the swarm.
    pub async fn stop_listening(&self) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let res = actor.send(network_msg::StopListening).await;
        unwrap_or_err!(res);
        ResultMessage::OK
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(&self) -> ResultMessage<SwarmInfo> {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let res = actor.send(network_msg::GetSwarmInfo).await;
        let info = unwrap_or_err!(res);
        ResultMessage::Ok(info)
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by the address if one is provided, or by peer id
    /// if the peer is already known e.g. from multicast DNS.
    /// If the peer is not a relay and can not be reached directly, it will be attempted to reach it via the relays,
    /// if there are any.
    /// Relays can be used to listen for incoming request, or to connect to a remote peer that can not
    /// be reached directly, and is listening to the same relay.
    /// Once the peer was successfully added, it can be used as target for operations on the remote stronghold.
    pub async fn add_peer(
        &self,
        peer: PeerId,
        address: Option<Multiaddr>,
        is_listening_relay: bool,
        is_dialing_relay: bool,
    ) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };

        if is_listening_relay {
            let res = actor
                .send(network_msg::StartListeningRelay {
                    relay: peer,
                    relay_addr: address,
                })
                .await;
            unwrap_result_msg!(res);
        } else {
            if let Some(address) = address {
                let res = actor.send(network_msg::AddPeerAddr { peer, address }).await;
                unwrap_or_err!(res);
            }

            let res = actor.send(network_msg::ConnectPeer { peer }).await;
            unwrap_result_msg!(res);
        }

        if is_dialing_relay {
            let res = actor.send(network_msg::AddDialingRelay { relay: peer }).await;
            unwrap_or_err!(res);
        }
        StatusMessage::OK
    }

    /// Remove a peer from the list of peers used for dialing, and / or stop listening with the relay.
    pub async fn remove_relay(&self, relay: PeerId, rm_listening_relay: bool, rm_dialing_relay: bool) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };

        if rm_listening_relay {
            let res = actor.send(network_msg::StopListeningRelay { relay }).await;
            unwrap_or_err!(res);
        }

        if rm_dialing_relay {
            let res = actor.send(network_msg::RemoveDialingRelay { relay }).await;
            unwrap_or_err!(res);
        }
        StatusMessage::OK
    }

    /// Change the firewall rule for specific peers, optionally also set it as the default rule, which applies if there
    /// are no specific rules for a peer. All inbound requests from the peers that this rule applies to, will be
    /// approved/ rejected based on this rule.
    pub async fn set_firewall_rule(
        &self,
        rule: Rule<ShRequest>,
        peers: Vec<PeerId>,
        set_default: bool,
    ) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };

        for peer in peers {
            let res = actor
                .send(network_msg::SetFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                    rule: rule.clone(),
                })
                .await;
            unwrap_or_err!(res);
        }
        if set_default {
            let res = actor
                .send(network_msg::SetFirewallDefault {
                    direction: RuleDirection::Inbound,
                    rule,
                })
                .await;
            unwrap_or_err!(res);
        }
        StatusMessage::OK
    }

    /// Remove peer specific rules from the firewall configuration.
    pub async fn remove_firewall_rules(&self, peers: Vec<PeerId>) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        for peer in peers {
            let res = actor
                .send(network_msg::RemoveFirewallRule {
                    peer,
                    direction: RuleDirection::Inbound,
                })
                .await;
            unwrap_or_err!(res);
        }
        StatusMessage::OK
    }

    /// Write to the vault of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_remote_vault(
        &self,
        peer: PeerId,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };

        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        // check if vault exists

        let send_request = network_msg::SendRequest {
            peer,
            request: CheckVault { vault_path },
        };
        let vault_exists = unwrap_result_msg!(actor.send(send_request).await);

        // no vault so create new one before writing.
        if !vault_exists {
            let send_request = network_msg::SendRequest {
                peer,
                request: CreateVault {
                    location: location.clone(),
                },
            };
            unwrap_result_msg!(actor.send(send_request).await);
        }

        // write data
        let send_request = network_msg::SendRequest {
            peer,
            request: WriteToVault {
                location: location.clone(),
                payload: payload.clone(),
                hint,
            },
        };

        match unwrap_result_msg!(actor.send(send_request).await) {
            Ok(_) => StatusMessage::OK,
            Err(e) => StatusMessage::Error(e.to_string()),
        }
    }

    /// Write to the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_to_remote_store(
        &self,
        peer: PeerId,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let send_request = network_msg::SendRequest {
            peer,
            request: WriteToStore {
                location,
                payload,
                lifetime,
            },
        };
        match unwrap_result_msg!(actor.send(send_request).await) {
            Ok(_) => StatusMessage::OK,
            Err(e) => StatusMessage::Error(e.to_string()),
        }
    }

    /// Read from the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn read_from_remote_store(&self, peer: PeerId, location: Location) -> ResultMessage<Vec<u8>> {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let send_request = network_msg::SendRequest {
            peer,
            request: ReadFromStore { location },
        };
        match unwrap_result_msg!(actor.send(send_request).await) {
            Ok(res) => ResultMessage::Ok(res),
            Err(e) => ResultMessage::Error(e.to_string()),
        }
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer: PeerId,
        vault_path: V,
    ) -> ResultMessage<Vec<(RecordId, RecordHint)>> {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let send_request = network_msg::SendRequest {
            peer,
            request: ListIds {
                vault_path: vault_path.into(),
            },
        };
        match unwrap_result_msg!(actor.send(send_request).await) {
            Ok(res) => ResultMessage::Ok(res),
            Err(e) => ResultMessage::Error(e.to_string()),
        }
    }

    /// Executes a runtime command at a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn remote_runtime_exec(&self, peer: PeerId, control_request: Procedure) -> ResultMessage<ProcResult> {
        let actor = match self.registry.send(GetNetwork).await.unwrap() {
            Some(a) => a,
            None => return ResultMessage::Error("No network actor spawned.".into()),
        };
        let send_request = network_msg::SendRequest {
            peer,
            request: CallProcedure { proc: control_request },
        };
        let receive_response = unwrap_or_err!(actor.send(send_request).await);
        let result = unwrap_or_err!(receive_response);
        match result {
            Ok(ok) => ResultMessage::Ok(ok),
            Err(err) => ResultMessage::Error(err.to_string()),
        }
    }
}

/// Implementation for remote synchronization on top of p2p.
#[cfg(feature = "p2p")]

impl Stronghold {
    /// Synchronizes with a remote peer
    ///
    /// This call runs through the synchronization protocol:
    /// All vault entries will be taken to calculate a shape of each entry, that consists of its
    /// size, location and hash value.
    pub async fn synchronize_with_remote<K>(
        &mut self,
        _peer: PeerId,
        _entries: Vec<Location>,
        _key: K,
        _client_id: ClientId,
    ) -> ResultMessage<()>
    where
        K: Zeroize + AsRef<Vec<u8>>,
    {
        // let network_actor = match self.registry.send(GetNetwork).await.unwrap() {
        //     Some(a) => a,
        //     None => return ResultMessage::Error("No network actor spawned.".into()),
        // };

        // // calculate shapes
        // let shapes = match self.snapshot_protocol_export_shapes(entries).await {
        //     Ok(s) => s,
        //     Err(error) => return ResultMessage::Error(error.to_string()),
        // };

        // let message = network_msg::SendRequest {
        //     peer,
        //     request: SynchronizeRemote { entries: shapes, key }, // SynchronizeWith
        // };

        // // TODO implement calculate_complement message handler on network actor side
        // // the expected return value should be the encrypted messae
        // let input: Vec<u8> = match network_actor.send(message).await {
        //     Ok(result) => result,
        //     Err(error) => return ResultMessage::Error(error.to_string()),
        // };

        // // import the remote entries
        // match self.snapshot_protocol_import_snapshot(input, &key, client_id).await {
        //     Ok(_) => ResultMessage::Ok(()),
        //     Err(error) => ResultMessage::Error(error.to_string()),
        // }

        ResultMessage::Ok(())
    }
}

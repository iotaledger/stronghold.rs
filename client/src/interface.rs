// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use futures::future::RemoteHandle;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use zeroize::Zeroize;

use engine::vault::RecordHint;

use crate::{
    actors::{InternalActor, InternalMsg, ProcResult, Procedure, SHRequest, SHResults},
    client::{Client, ClientMsg},
    line_error,
    snapshot::Snapshot,
    utils::{ask, LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
    ClientId, Location, Provider,
};

/// Main Interface for the Stronghold System. Contains the Riker Actor System, a vector of the current attached
/// ClientIds and ActorRefs, a HashMap of the derive data (SHA512 of the client_path) and an index for the Current
/// target actor.
pub struct Stronghold {
    // actor system.
    pub system: ActorSystem,
    // clients in the system.
    client_ids: Vec<ClientId>,

    // Actor references in the system.
    actors: Vec<ActorRef<ClientMsg>>,

    // data derived from the client_paths.
    derive_data: HashMap<Vec<u8>, Vec<u8>>,

    // current index of the client.
    current_target: usize,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor. Accepts a `ActorSystem`, the first
    /// client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
    pub fn init_stronghold_system(system: ActorSystem, client_path: Vec<u8>, _options: Vec<StrongholdFlags>) -> Self {
        let client_id = ClientId::load_from_path(&client_path, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let client_ids = vec![client_id];

        let mut derive_data = HashMap::new();

        derive_data.insert(client_path.clone(), client_path);

        let client = system
            .actor_of_args::<Client, _>(&id_str, client_id)
            .expect(line_error!());

        system
            .actor_of_args::<InternalActor<Provider>, _>(&format!("internal-{}", id_str), client_id)
            .expect(line_error!());

        system.actor_of::<Snapshot>("snapshot").expect(line_error!());

        let actors = vec![client];

        Self {
            system,
            client_ids,
            derive_data,
            actors,
            current_target: 0,
        }
    }

    /// Spawns a new set of actors for the Stronghold system. Accepts the client_path: `Vec<u8>` and the options:
    /// `StrongholdFlags`
    pub fn spawn_stronghold_actor(&mut self, client_path: Vec<u8>, _options: Vec<StrongholdFlags>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());
        let id_str: String = client_id.into();
        let counter = self.actors.len();

        if self.client_ids.contains(&client_id) {
            self.switch_actor_target(client_path);
        } else {
            let client = self
                .system
                .actor_of_args::<Client, _>(&id_str, client_id)
                .expect(line_error!());
            self.system
                .actor_of_args::<InternalActor<Provider>, _>(&format!("internal-{}", id_str), client_id)
                .expect(line_error!());

            self.actors.push(client);
            self.client_ids.push(client_id);
            self.derive_data.insert(client_path.clone(), client_path);
            self.current_target = counter;
        }

        StatusMessage::OK
    }

    /// Switches the actor target to another actor in the system specified by the client_path: `Vec<u8>`.
    pub fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if self.client_ids.contains(&client_id) {
            let idx = self.client_ids.iter().position(|cid| cid == &client_id);

            if let Some(idx) = idx {
                self.current_target = idx;
            }

            StatusMessage::OK
        } else {
            StatusMessage::Error("Unable to find the actor with that client path".into())
        }
    }

    /// Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified
    /// location of `Location` type. The payload must be specified as a `Vec<u8>` and a `RecordHint` can be provided.
    /// Also accepts `VaultFlags` for when a new Vault is created.
    pub async fn write_to_vault(
        &self,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        if let SHResults::ReturnExistsVault(b) =
            ask(&self.system, client, SHRequest::CheckVault(vault_path.clone())).await
        {
            // check if vault exists
            if b {
                if let SHResults::ReturnExistsRecord(b) = ask(
                    &self.system,
                    client,
                    SHRequest::CheckRecord {
                        location: location.clone(),
                    },
                )
                .await
                {
                    if b {
                        if let SHResults::ReturnWriteVault(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteToVault {
                                location: location.clone(),
                                payload: payload.clone(),
                                hint,
                            },
                        )
                        .await
                        {
                            return status;
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    } else {
                        let (_idx, _) = if let SHResults::ReturnInitRecord(status) = ask(
                            &self.system,
                            client,
                            SHRequest::InitRecord {
                                location: location.clone(),
                            },
                        )
                        .await
                        {
                            (Some(idx), status)
                        } else {
                            (None, StatusMessage::Error("Unable to initialize record".into()))
                        };

                        if let SHResults::ReturnWriteVault(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteToVault {
                                location: location.clone(),
                                payload: payload.clone(),
                                hint,
                            },
                        )
                        .await
                        {
                            return status;
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    }
                };
            } else {
                // no vault so create new one before writing.
                if let SHResults::ReturnCreateVault(status) =
                    ask(&self.system, client, SHRequest::CreateNewVault(location.clone())).await
                {
                    status
                } else {
                    return StatusMessage::Error("Invalid Message".into());
                };

                if let SHResults::ReturnWriteVault(status) = ask(
                    &self.system,
                    client,
                    SHRequest::WriteToVault {
                        location,
                        payload,
                        hint,
                    },
                )
                .await
                {
                    return status;
                } else {
                    return StatusMessage::Error("Error Writing data".into());
                };
            }
        };

        StatusMessage::Error("Failed to write the data".into())
    }

    /// A test function for reading data from a vault.
    #[cfg(test)]
    pub async fn read_secret(&self, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::ReadFromVault { location }).await;

        if let SHResults::ReturnReadVault(payload, status) = res {
            (Some(payload), status)
        } else {
            (None, StatusMessage::Error("Unable to read data".into()))
        }
    }

    /// Writes data into an insecure cache.  This method, accepts a `Location`, a `Vec<u8>` and an optional `Duration`.
    /// The lifetime allows the data to be deleted after the specified duration has passed.  If not lifetime is
    /// specified, the data will persist until it is manually deleted or over-written. Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn write_to_store(
        &self,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(
            &self.system,
            client,
            SHRequest::WriteToStore {
                location,
                payload,
                lifetime,
            },
        )
        .await;

        if let SHResults::ReturnWriteStore(status) = res {
            status
        } else {
            StatusMessage::Error("Failed to write to the store".into())
        }
    }

    /// A method that reads from an insecure cache.  This method, accepts a `Location` and returns the payload in the
    /// form of a `Vec<u8>`.  If the location does not exist, an empty vector will be returned along with an error
    /// `StatusMessage`.  Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn read_from_store(&self, location: Location) -> (Vec<u8>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::ReadFromStore { location }).await;

        if let SHResults::ReturnReadStore(payload, status) = res {
            (payload, status)
        } else {
            (vec![], StatusMessage::Error("Failed to read from the store".into()))
        }
    }

    /// A method to delete data from an insecure cache. This method, accepts a `Location` and returns a `StatusMessage`.
    /// Note: One store is mapped to one client. Can specify the same location across multiple clients.
    pub async fn delete_from_store(&self, location: Location) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::DeleteFromStore(location)).await;

        if let SHResults::ReturnDeleteStore(status) = res {
            status
        } else {
            StatusMessage::Error("Failed to delete from the store".into())
        }
    }

    /// Revokes the data from the specified location of type `Location`. Revoked data is not readable and can be removed
    /// from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call with
    /// automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(&self, location: Location, should_gc: bool) -> StatusMessage {
        let idx = self.current_target;
        let status;
        let client = &self.actors[idx];
        let vault_path = location.vault_path().to_vec();

        if should_gc {
            let _ = if let SHResults::ReturnRevoke(status) =
                ask(&self.system, client, SHRequest::RevokeData { location }).await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            status = if let SHResults::ReturnGarbage(status) =
                ask(&self.system, client, SHRequest::GarbageCollect(vault_path.clone())).await
            {
                status
            } else {
                return StatusMessage::Error("Failed to garbage collect the vault".into());
            };

            status
        } else {
            status = if let SHResults::ReturnRevoke(status) =
                ask(&self.system, client, SHRequest::RevokeData { location }).await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            status
        }
    }

    /// Garbage collects any revokes in a Vault based on the given vault_path and the current target actor.
    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnGarbage(status) = ask(&self.system, client, SHRequest::GarbageCollect(vault_path)).await
        {
            status
        } else {
            StatusMessage::Error("Failed to garbage collect the vault".into())
        }
    }

    /// Returns a list of the available records and their `RecordHint` values in a vault by the given vault_path.
    /// Records are returned as `usize` based on their index if they are written with counter `Locations`.  Generic
    /// `Locations` will not return a readable index.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> (Vec<(usize, RecordHint)>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnList(ids, status) =
            ask(&self.system, client, SHRequest::ListIds(vault_path.into())).await
        {
            (ids, status)
        } else {
            (
                vec![],
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            )
        }
    }

    /// Executes a runtime command given a `Procedure`.  Returns a `ProcResult` based off of the control_request
    /// specified.
    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        let idx = self.current_target;

        let client = &self.actors[idx];
        let shr = ask(&self.system, client, SHRequest::ControlRequest(control_request)).await;
        match shr {
            SHResults::ReturnControlRequest(pr) => pr,
            _ => todo!("return a proper error: unexpected result"),
        }
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
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let former_cid = if let Some(cp) = former_client_path {
            self.derive_data.insert(cp.clone(), cp.clone());

            Some(ClientId::load_from_path(&cp, &cp).expect(line_error!()))
        } else {
            None
        };

        let idx = self.client_ids.iter().position(|id| id == &client_id);
        if let Some(idx) = idx {
            let client = &self.actors[idx];

            let mut key: [u8; 32] = [0u8; 32];

            let keydata = keydata.as_ref();

            key.copy_from_slice(keydata);

            if let SHResults::ReturnReadSnap(status) = ask(
                &self.system,
                client,
                SHRequest::ReadSnapshot {
                    key,
                    filename,
                    path,
                    cid: client_id,
                    former_cid,
                },
            )
            .await
            {
                status
            } else {
                StatusMessage::Error("Unable to read snapshot".into())
            }
        } else {
            StatusMessage::Error("Unable to find client actor".into())
        }
    }

    // pub async fn write_snapshot(
    //     &self,
    //     _client_path: Vec<u8>,
    //     _keydata: Vec<u8>,
    //     _filename: Option<String>,
    //     _path: Option<PathBuf>,
    //     _duration: Option<Duration>,
    // ) -> StatusMessage {
    //     // let data = self.derive_data.get(&client_path).expect(line_error!());
    //     // let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

    //     // let idx = self.client_ids.iter().position(|id| id == &client_id);
    //     // if let Some(idx) = idx {
    //     //     let client = &self.actors[idx];

    //     //     let mut key: [u8; 32] = [0u8; 32];

    //     //     key.copy_from_slice(&keydata);

    //     //     if let SHResults::ReturnWriteSnap(status) =
    //     //         ask(&self.system, client, SHRequest::WriteSnapshot { key, filename, path }).await
    //     //     {
    //     //         status
    //     //     } else {
    //     //         StatusMessage::Error("Unable to read snapshot".into())
    //     //     }
    //     // } else {
    //     //     StatusMessage::Error("Unable to find client actor".into())
    //     // }

    //     unimplemented!()
    // }

    /// Writes the entire state of the `Stronghold` into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let num_of_actors = self.actors.len();
        let idx = self.current_target;
        let client = &self.actors[idx];

        let mut futures = vec![];
        let mut key: [u8; 32] = [0u8; 32];

        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        if num_of_actors != 0 {
            for (_, actor) in self.actors.iter().enumerate() {
                let res: RemoteHandle<SHResults> = ask(&self.system, actor, SHRequest::FillSnapshot);
                futures.push(res);
            }
        } else {
            return StatusMessage::Error("Unable to write snapshot without any actors.".into());
        }

        for fut in futures {
            fut.await;
        }

        let res: SHResults = ask(&self.system, client, SHRequest::WriteSnapshot { key, filename, path }).await;

        if let SHResults::ReturnWriteSnap(status) = res {
            status
        } else {
            StatusMessage::Error("Unable to write snapshot".into())
        }
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true` both the internal actor and the client actor will be killed.  Otherwise, the cache of the
    /// current target actor will be cleared.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StatusMessage {
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let idx = self.client_ids.iter().position(|id| id == &client_id);

        let client_str: String = client_id.into();

        if let Some(idx) = idx {
            if kill_actor {
                let client = &self.actors.remove(idx);
                self.client_ids.remove(idx);
                self.derive_data.remove(&client_path).expect(line_error!());

                self.system.stop(client);
                let internal = self
                    .system
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());
                internal.try_tell(InternalMsg::KillInternal, None);

                StatusMessage::OK
            } else {
                let client = &self.actors[idx];

                if let SHResults::ReturnClearCache(status) = ask(&self.system, client, SHRequest::ClearCache).await {
                    status
                } else {
                    StatusMessage::Error("Unable to clear the cache".into())
                }
            }
        } else {
            StatusMessage::Error("Unable to find client actor".into())
        }
    }

    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }
}

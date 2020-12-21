// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{collections::HashMap, path::PathBuf, time::Duration};

use engine::vault::RecordHint;

use crate::{
    actors::{InternalActor, InternalMsg, ProcResult, Procedure, SHRequest, SHResults},
    client::{Client, ClientMsg},
    line_error,
    snapshot::Snapshot,
    utils::{ask, LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
    ClientId, Location, Provider,
};

pub struct Stronghold {
    // actor system.
    pub system: ActorSystem,
    // clients in the system.
    client_ids: Vec<ClientId>,

    actors: Vec<ActorRef<ClientMsg>>,

    derive_data: HashMap<Vec<u8>, Vec<u8>>,

    // current index of the client.
    current_target: usize,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor.
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

    /// Starts actor model and sets current_target actor.  Can be used to add another stronghold actor to the system if
    /// called a 2nd time.
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

    pub async fn write_data(
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
                        if let SHResults::ReturnWriteData(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteData {
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

                        if let SHResults::ReturnWriteData(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteData {
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

                if let SHResults::ReturnWriteData(status) = ask(
                    &self.system,
                    client,
                    SHRequest::WriteData {
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

    pub async fn read_data(&self, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(&self.system, client, SHRequest::ReadData { location }).await;

        if let SHResults::ReturnReadData(payload, status) = res {
            (Some(payload), status)
        } else {
            (None, StatusMessage::Error("Unable to read data".into()))
        }
    }

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

    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        let idx = self.current_target;

        let client = &self.actors[idx];
        let shr = ask(&self.system, client, SHRequest::ControlRequest(control_request)).await;
        match shr {
            SHResults::ReturnControlRequest(pr) => pr,
            _ => todo!("return a proper error: unexpected result"),
        }
    }

    pub async fn read_snapshot(
        &mut self,
        client_path: Vec<u8>,
        former_client_path: Option<Vec<u8>>,
        keydata: Vec<u8>,
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

            key.copy_from_slice(&keydata);

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

    pub async fn write_snapshot(
        &self,
        _client_path: Vec<u8>,
        _keydata: Vec<u8>,
        _filename: Option<String>,
        _path: Option<PathBuf>,
        _duration: Option<Duration>,
    ) -> StatusMessage {
        // let data = self.derive_data.get(&client_path).expect(line_error!());
        // let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        // let idx = self.client_ids.iter().position(|id| id == &client_id);
        // if let Some(idx) = idx {
        //     let client = &self.actors[idx];

        //     let mut key: [u8; 32] = [0u8; 32];

        //     key.copy_from_slice(&keydata);

        //     if let SHResults::ReturnWriteSnap(status) =
        //         ask(&self.system, client, SHRequest::WriteSnapshot { key, filename, path }).await
        //     {
        //         status
        //     } else {
        //         StatusMessage::Error("Unable to read snapshot".into())
        //     }
        // } else {
        //     StatusMessage::Error("Unable to find client actor".into())
        // }

        unimplemented!()
    }

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

    pub async fn write_all_to_snapshot(
        &mut self,
        keydata: Vec<u8>,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let num_of_actors = self.actors.len();

        if num_of_actors != 0 {
            for (idx, actor) in self.actors.iter().enumerate() {
                let mut key: [u8; 32] = [0u8; 32];

                key.copy_from_slice(&keydata);

                if idx < num_of_actors - 1 {
                    let _: SHResults = ask(
                        &self.system,
                        actor,
                        SHRequest::WriteSnapshotAll {
                            key,
                            filename: filename.clone(),
                            path: path.clone(),
                            is_final: false,
                        },
                    )
                    .await;
                } else if let SHResults::ReturnWriteSnap(status) = ask(
                    &self.system,
                    actor,
                    SHRequest::WriteSnapshotAll {
                        key,
                        filename: filename.clone(),
                        path: path.clone(),
                        is_final: true,
                    },
                )
                .await
                {
                    return status;
                } else {
                    return StatusMessage::Error("Unable to write snapshot without any actors.".into());
                };
            }
        } else {
            return StatusMessage::Error("Unable to write snapshot without any actors.".into());
        }

        StatusMessage::Error("Unable to write snapshot".into())
    }

    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }
}

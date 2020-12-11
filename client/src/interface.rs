// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use futures::future::RemoteHandle;

use std::{collections::HashMap, path::PathBuf, time::Duration};

use engine::vault::{RecordHint, RecordId};

use crate::{
    actors::{InternalActor, Procedure, SHRequest, SHResults},
    client::{Client, ClientMsg},
    line_error,
    snapshot::Snapshot,
    utils::{ask, index_of_unchecked, LoadFromPath, StatusMessage, StrongholdFlags},
    ClientId, Provider,
};

pub struct Stronghold {
    // actor system.
    system: ActorSystem,
    // clients in the system.
    client_ids: Vec<ClientId>,

    actors: Vec<ActorRef<ClientMsg>>,

    // client path bytes and keydata
    data: HashMap<Vec<u8>, Vec<u8>>,
    // current index of the client.
    current_target: usize,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor.
    pub fn init_stronghold_system(
        system: ActorSystem,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> Self {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let client_ids = vec![client_id];
        let mut data: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

        data.insert(client_path, keydata);

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
            actors,
            data,
            current_target: 0,
        }
    }

    /// Starts actor model and sets current_target actor.  Can be used to add another stronghold actor to the system if
    /// called a 2nd time.
    pub fn spawn_stronghold_actor(
        &mut self,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let counter = self.actors.len();

        if self.client_ids.contains(&client_id) {
            self.current_target = index_of_unchecked(&self.client_ids, &client_id);
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
            self.data.insert(client_path, keydata);

            self.current_target = counter;
        }

        StatusMessage::Ok
    }

    pub async fn write_data(
        &self,
        data: Vec<u8>,
        vault_path: Vec<u8>,
        record_counter: Option<usize>,
        hint: RecordHint,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnExistsVault(b) =
            ask(&self.system, client, SHRequest::CheckVault(vault_path.clone())).await
        {
            // check if vault exists
            if b {
                if let SHResults::ReturnExistsRecord(b) = ask(
                    &self.system,
                    client,
                    SHRequest::CheckRecord(vault_path.clone(), record_counter),
                )
                .await
                {
                    if b {
                        if let SHResults::ReturnWriteData(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteData(vault_path.clone(), record_counter, data.clone(), hint),
                        )
                        .await
                        {
                            status
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    } else {
                        let (idx, _) = if let SHResults::ReturnInitRecord(idx, status) =
                            ask(&self.system, client, SHRequest::InitRecord(vault_path.clone())).await
                        {
                            (Some(idx), status)
                        } else {
                            (None, StatusMessage::Error("Unable to initialize record".into()))
                        };

                        if let SHResults::ReturnWriteData(status) = ask(
                            &self.system,
                            client,
                            SHRequest::WriteData(vault_path.clone(), idx, data.clone(), hint),
                        )
                        .await
                        {
                            status
                        } else {
                            return StatusMessage::Error("Error Writing data".into());
                        };
                    }
                };

                if let SHResults::ReturnWriteData(status) = ask(
                    &self.system,
                    client,
                    SHRequest::WriteData(vault_path, record_counter, data, hint),
                )
                .await
                {
                    status
                } else {
                    return StatusMessage::Error("Error Writing data".into());
                };
            } else {
                // no vault so create new one before writing.
                if let SHResults::ReturnCreateVault(status) =
                    ask(&self.system, client, SHRequest::CreateNewVault(vault_path.clone())).await
                {
                    status
                } else {
                    return StatusMessage::Error("Invalid Message".into());
                };

                if let SHResults::ReturnWriteData(status) = ask(
                    &self.system,
                    client,
                    SHRequest::WriteData(vault_path, record_counter, data, hint),
                )
                .await
                {
                    status
                } else {
                    return StatusMessage::Error("Error Writing data".into());
                };
            }
        };

        StatusMessage::Ok
    }

    pub async fn read_data(
        &self,
        vault_path: Vec<u8>,
        record_counter: Option<usize>,
    ) -> (Option<Vec<u8>>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        let res: SHResults = ask(
            &self.system,
            client,
            SHRequest::ReadData(vault_path.clone(), record_counter),
        )
        .await;

        if let SHResults::ReturnReadData(payload, status) = res {
            (Some(payload), status)
        } else {
            (None, StatusMessage::Error("Unable to read data".into()))
        }
    }

    pub async fn delete_data(&self, vault_path: Vec<u8>, record_counter: usize, should_gc: bool) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];
        if should_gc {
            let status = if let SHResults::ReturnRevoke(status) = ask(
                &self.system,
                client,
                SHRequest::RevokeData(vault_path.clone(), record_counter),
            )
            .await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            let status = if let SHResults::ReturnGarbage(status) =
                ask(&self.system, client, SHRequest::GarbageCollect(vault_path.clone())).await
            {
                status
            } else {
                return StatusMessage::Error("Failed to garbage collect the vault".into());
            };

            return status;
        } else {
            let status = if let SHResults::ReturnRevoke(status) =
                ask(&self.system, client, SHRequest::RevokeData(vault_path, record_counter)).await
            {
                status
            } else {
                return StatusMessage::Error("Could not revoke data".into());
            };

            return status;
        }
    }

    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnGarbage(status) = ask(&self.system, client, SHRequest::GarbageCollect(vault_path)).await
        {
            return status;
        } else {
            return StatusMessage::Error("Failed to garbage collect the vault".into());
        }
    }

    pub async fn list_hints_and_ids(&self, vault_path: Vec<u8>) -> (Vec<(usize, RecordHint)>, StatusMessage) {
        let idx = self.current_target;

        let client = &self.actors[idx];

        if let SHResults::ReturnList(ids, status) = ask(&self.system, client, SHRequest::ListIds(vault_path)).await {
            return (ids, status);
        } else {
            return (
                vec![],
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            );
        }
    }

    pub async fn runtime_exec(&self, control_request: Procedure) -> StatusMessage {
        unimplemented!()
    }

    pub async fn read_snapshot(
        &self,
        client_path: Vec<u8>,
        name: Option<String>,
        path: Option<PathBuf>,
        new_stronghold: bool,
        _options: Option<Vec<StrongholdFlags>>,
    ) -> StatusMessage {
        if new_stronghold {
            unimplemented!()
        } else {
            let keydata = self.data.get(&client_path);
            if let Some(keydata) = keydata {
                let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());

                let idx = self.client_ids.iter().position(|id| id == &client_id);
                if let Some(idx) = idx {
                    let client = &self.actors[idx];

                    let mut key: [u8; 32] = [0u8; 32];

                    key.copy_from_slice(keydata);

                    if let SHResults::ReturnReadSnap(status) =
                        ask(&self.system, client, SHRequest::ReadSnapshot(key, name, path)).await
                    {
                        return status;
                    } else {
                        return StatusMessage::Error("Unable to read snapshot".into());
                    }
                } else {
                    return StatusMessage::Error("Unable to find client actor".into());
                }
            } else {
                return StatusMessage::Error("Failed to retrieve keydata, try another client_path".into());
            }
        }
    }

    pub async fn write_snapshot(
        &self,
        client_path: Vec<u8>,
        name: Option<String>,
        path: Option<PathBuf>,
        _duration: Option<Duration>,
    ) -> StatusMessage {
        let keydata = self.data.get(&client_path);
        if let Some(keydata) = keydata {
            let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());

            let idx = self.client_ids.iter().position(|id| id == &client_id);
            if let Some(idx) = idx {
                let client = &self.actors[idx];

                let mut key: [u8; 32] = [0u8; 32];

                key.copy_from_slice(keydata);

                if let SHResults::ReturnWriteSnap(status) =
                    ask(&self.system, client, SHRequest::WriteSnapshot(key, name, path)).await
                {
                    return status;
                } else {
                    return StatusMessage::Error("Unable to read snapshot".into());
                }
            } else {
                return StatusMessage::Error("Unable to find client actor".into());
            }
        } else {
            return StatusMessage::Error("Failed to retrieve keydata, try another client_path".into());
        }

        StatusMessage::Ok
    }

    pub async fn kill_stronghold(&self, client_path: Vec<u8>, kill_actor: bool, write_snapshot: bool) -> StatusMessage {
        unimplemented!()
    }

    fn check_config_flags() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use riker::actors::*;

    use super::*;

    // use crate::client::{Client, SHRequest};

    // use futures::executor::block_on;

    #[test]
    fn test_stronghold() {
        let sys = ActorSystem::new().unwrap();
        let vault_path = b"path".to_vec();
        let client_path = b"test".to_vec();
        let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

        let stronghold = Stronghold::init_stronghold_system(sys, key_data, client_path.clone(), vec![]);

        // Write at the first record of the vault using Some(0).  Also creates the new vault.
        futures::executor::block_on(stronghold.write_data(
            b"test".to_vec(),
            vault_path.clone(),
            Some(0),
            RecordHint::new(b"first hint").expect(line_error!()),
        ));

        // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
        futures::executor::block_on(stronghold.write_data(
            b"another test".to_vec(),
            vault_path.clone(),
            None,
            RecordHint::new(b"another hint").expect(line_error!()),
        ));

        futures::executor::block_on(stronghold.write_data(
            b"yet another test".to_vec(),
            vault_path.clone(),
            None,
            RecordHint::new(b"yet another hint").expect(line_error!()),
        ));

        // Read the first record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(vault_path.clone(), Some(0)));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

        // Read the head record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(vault_path.clone(), None));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));

        println!("{:?}", ids);

        futures::executor::block_on(stronghold.delete_data(vault_path.clone(), 0, false));

        // attempt to read the first record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(vault_path.clone(), Some(0)));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

        futures::executor::block_on(stronghold.garbage_collect(vault_path.clone()));

        futures::executor::block_on(stronghold.write_snapshot(client_path.clone(), None, None, None));

        futures::executor::block_on(stronghold.read_snapshot(client_path, None, None, false, None));

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));

        println!("{:?}", ids);

        let (p, _) = futures::executor::block_on(stronghold.read_data(vault_path.clone(), Some(2)));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));
    }
}

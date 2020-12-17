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
    utils::{ask, index_of_unchecked, LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
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
            self.current_target = index_of_unchecked(&self.client_ids, &client_id);
        } else {
            let client = self
                .system
                .actor_of_args::<Client, _>(&id_str, client_id)
                .expect(line_error!());
            &self
                .system
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
                    ask(&self.system, client, SHRequest::CreateNewVault(vault_path.clone())).await
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
        &self,
        client_path: Vec<u8>,
        keydata: Vec<u8>,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let idx = self.client_ids.iter().position(|id| id == &client_id);
        if let Some(idx) = idx {
            let client = &self.actors[idx];

            let mut key: [u8; 32] = [0u8; 32];

            key.copy_from_slice(&keydata);

            if let SHResults::ReturnReadSnap(status) =
                ask(&self.system, client, SHRequest::ReadSnapshot { key, filename, path }).await
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
        client_path: Vec<u8>,
        keydata: Vec<u8>,
        filename: Option<String>,
        path: Option<PathBuf>,
        _duration: Option<Duration>,
    ) -> StatusMessage {
        let data = self.derive_data.get(&client_path).expect(line_error!());
        let client_id = ClientId::load_from_path(&data.as_ref(), &client_path).expect(line_error!());

        let idx = self.client_ids.iter().position(|id| id == &client_id);
        if let Some(idx) = idx {
            let client = &self.actors[idx];

            let mut key: [u8; 32] = [0u8; 32];

            key.copy_from_slice(&keydata);

            if let SHResults::ReturnWriteSnap(status) =
                ask(&self.system, client, SHRequest::WriteSnapshot { key, filename, path }).await
            {
                status
            } else {
                StatusMessage::Error("Unable to read snapshot".into())
            }
        } else {
            StatusMessage::Error("Unable to find client actor".into())
        }
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

                &self.system.stop(client);
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

    pub async fn write_all_actors_to_snapshot(
        &mut self,
        _keydata: Vec<u8>,
        _filename: Option<String>,
        _path: Option<PathBuf>,
    ) -> StatusMessage {
        unimplemented!();
    }

    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use riker::actors::*;

    use super::*;

    use crate::{
        actors::SLIP10DeriveInput,
        utils::{hd, ResultMessage},
        Location,
    };

    #[test]
    fn test_stronghold() {
        let sys = ActorSystem::new().unwrap();
        let vault_path = b"path".to_vec();
        let client_path = b"test".to_vec();

        let loc0 = Location::counter::<_, usize>("path", Some(0));
        let loc1 = Location::counter::<_, usize>("path", Some(1));
        let loc2 = Location::counter::<_, usize>("path", Some(2));
        let lochead = Location::counter::<_, usize>("path", None);

        let slip10_seed = Location::generic("slip10", "seed");
        let slip10_key = Location::generic("slip10", "key");
        let bip39_seed = Location::generic("bip39", "seed");
        let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();

        let mut stronghold = Stronghold::init_stronghold_system(sys, client_path.clone(), vec![]);

        // Write at the first record of the vault using Some(0).  Also creates the new vault.
        futures::executor::block_on(stronghold.write_data(
            loc0.clone(),
            b"test".to_vec(),
            RecordHint::new(b"first hint").expect(line_error!()),
            vec![],
        ));

        // read head.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

        // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
        futures::executor::block_on(stronghold.write_data(
            loc1.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"another hint").expect(line_error!()),
            vec![],
        ));

        // read head.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

        futures::executor::block_on(stronghold.write_data(
            loc2.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"yet another hint").expect(line_error!()),
            vec![],
        ));

        // read head.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        // Read the first record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(loc0.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

        // Read the head record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(loc1.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

        let (p, _) = futures::executor::block_on(stronghold.read_data(loc2.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));
        println!("{:?}", ids);

        futures::executor::block_on(stronghold.delete_data(loc0.clone(), false));

        // attempt to read the first record of the vault.
        let (p, _) = futures::executor::block_on(stronghold.read_data(loc0.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

        match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10Generate {
            output: slip10_seed.clone(),
            hint: RecordHint::new(b"test_seed").expect(line_error!()),
        })) {
            ProcResult::SLIP10Generate(StatusMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }

        match futures::executor::block_on(stronghold.runtime_exec(Procedure::SLIP10Derive {
            chain: hd::Chain::from_u32_hardened(vec![]),
            input: SLIP10DeriveInput::Seed(slip10_seed.clone()),
            output: slip10_key.clone(),
            hint: RecordHint::new(b"test").expect(line_error!()),
        })) {
            ProcResult::SLIP10Derive(StatusMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }

        let pk = match futures::executor::block_on(stronghold.runtime_exec(Procedure::Ed25519PublicKey {
            key: slip10_key.clone(),
        })) {
            ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk)) => {
                crypto::ed25519::PublicKey::from_compressed_bytes(pk).expect(line_error!())
            }
            r => panic!("unexpected result: {:?}", r),
        };

        let msg = b"foobar";
        let sig = match futures::executor::block_on(stronghold.runtime_exec(Procedure::Ed25519Sign {
            key: slip10_key.clone(),
            msg: msg.to_vec(),
        })) {
            ProcResult::Ed25519Sign(ResultMessage::Ok(sig)) => crypto::ed25519::Signature::from_bytes(sig),
            r => panic!("unexpected result: {:?}", r),
        };

        assert!(crypto::ed25519::verify(&pk, &sig, msg));

        match futures::executor::block_on(stronghold.runtime_exec(Procedure::BIP39Recover {
            output: bip39_seed.clone(),
            hint: RecordHint::new(b"bip_seed").expect(line_error!()),
            mnemonic: "Some mnemonic value".into(),
            passphrase: Some("a passphrase".into()),
        })) {
            ProcResult::BIP39Recover(StatusMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }

        futures::executor::block_on(stronghold.garbage_collect(vault_path.clone()));

        futures::executor::block_on(stronghold.write_snapshot(client_path.clone(), key_data.clone(), None, None, None));

        futures::executor::block_on(stronghold.read_snapshot(client_path.clone(), key_data, None, None));

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path.clone()));
        println!("{:?}", ids);

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(slip10_seed.vault_path()));
        println!("{:?}", ids);

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(bip39_seed.vault_path()));
        println!("{:?}", ids);

        // read head after reading snapshot.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        let (p, _) = futures::executor::block_on(stronghold.read_data(loc2.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        let (p, _) = futures::executor::block_on(stronghold.read_data(loc0));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

        futures::executor::block_on(stronghold.kill_stronghold(client_path.clone(), false));

        let (p, _) = futures::executor::block_on(stronghold.read_data(loc2));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok(""));

        futures::executor::block_on(stronghold.kill_stronghold(client_path, true));

        stronghold.system.print_tree();
    }

    #[test]
    fn run_stronghold_multi_actors() {
        let sys = ActorSystem::new().unwrap();
        let key_data = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
        let client_path0 = b"test a".to_vec();
        let client_path1 = b"test b".to_vec();
        let client_path2 = b"test c".to_vec();

        let loc0 = Location::counter::<_, usize>("path", Some(0));
        let lochead = Location::counter::<_, usize>("path", None);

        let mut stronghold = Stronghold::init_stronghold_system(sys, client_path0.clone(), vec![]);

        stronghold.spawn_stronghold_actor(client_path1.clone(), vec![]);

        stronghold.switch_actor_target(client_path0.clone());

        futures::executor::block_on(stronghold.write_data(
            lochead.clone(),
            b"test".to_vec(),
            RecordHint::new(b"1").expect(line_error!()),
            vec![],
        ));

        // read head.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("test"));

        stronghold.switch_actor_target(client_path1.clone());

        // Write on the next record of the vault using None.  This calls InitRecord and creates a new one at index 1.
        futures::executor::block_on(stronghold.write_data(
            lochead.clone(),
            b"another test".to_vec(),
            RecordHint::new(b"1").expect(line_error!()),
            vec![],
        ));

        // read head.
        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

        stronghold.switch_actor_target(client_path0.clone());

        futures::executor::block_on(stronghold.write_data(
            lochead.clone(),
            b"yet another test".to_vec(),
            RecordHint::new(b"2").expect(line_error!()),
            vec![],
        ));

        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("yet another test"));

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
        println!("{:?}", ids);

        futures::executor::block_on(stronghold.write_snapshot(
            client_path0,
            key_data.clone(),
            Some("test_1".into()),
            None,
            None,
        ));

        stronghold.switch_actor_target(client_path1.clone());

        let (ids, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
        println!("{:?}", ids);

        futures::executor::block_on(stronghold.write_snapshot(
            client_path1.clone(),
            key_data.clone(),
            Some("test_2".into()),
            None,
            None,
        ));

        stronghold.spawn_stronghold_actor(client_path2.clone(), vec![]);

        futures::executor::block_on(stronghold.read_snapshot(
            client_path2.clone(),
            key_data,
            Some("test_2".into()),
            None,
        ));

        let (p, _) = futures::executor::block_on(stronghold.read_data(loc0));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("another test"));

        futures::executor::block_on(stronghold.write_data(
            lochead.clone(),
            b"a new actor test".to_vec(),
            RecordHint::new(b"first hint").expect(line_error!()),
            vec![],
        ));

        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test"));

        futures::executor::block_on(stronghold.write_data(
            lochead.clone(),
            b"a new actor test again".to_vec(),
            RecordHint::new(b"first hint").expect(line_error!()),
            vec![],
        ));

        let (p, _) = futures::executor::block_on(stronghold.read_data(lochead.clone()));

        assert_eq!(std::str::from_utf8(&p.unwrap()), Ok("a new actor test again"));

        let (ids3, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));

        stronghold.switch_actor_target(client_path1.clone());

        let (ids1, _) = futures::executor::block_on(stronghold.list_hints_and_ids(lochead.vault_path()));
        assert_ne!(ids3, ids1);

        stronghold.system.print_tree();
    }
}

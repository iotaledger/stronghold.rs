// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::ActorSystem;

use futures::future::RemoteHandle;

use std::{collections::HashMap, time::Duration};

use engine::vault::RecordHint;

use crate::{ask::ask, client::Procedure, ids::ClientId, line_error};

pub enum StatusMessage {
    Ok,
    Busy,
    Error,
}

pub enum StrongholdFlags {
    Readable(bool),
}

pub enum VaultFlags {}

pub struct Stronghold {
    // actor system.
    system: ActorSystem,
    // clients in the system.
    clients: Vec<ClientId>,
    // client id and keydata
    data: HashMap<ClientId, Vec<u8>>,
    // current target client.
    current_target: Option<ClientId>,
}

impl Stronghold {
    pub fn init_stronghold(mut system: ActorSystem) -> Self {
        Self {
            system,
            clients: vec![],
            data: HashMap::new(),
            current_target: None,
        }
    }

    /// Starts actor model and sets current_target actor.  Can be used to add another stronghold actor to the system if called a 2nd time.
    pub async fn start_stronghold(
        &mut self,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> (ActorSystem, StatusMessage) {
        self.add_client(keydata, client_path);

        //     sys.actor_of::<InternalActor<Provider>>("internal-actor").unwrap();
        //     sys.actor_of::<Snapshot>("snapshot").unwrap();
        //     sys.actor_of::<Runtime>("runtime").unwrap();
        //     sys.actor_of_args::<Client, _>("stronghold-internal", (chan.clone(), data, path))
        //         .unwrap();

        (self.system.clone(), StatusMessage::Ok)
    }

    pub async fn write_data(
        data: Vec<u8>,
        vault_path: Vec<u8>,
        record_counter: Option<usize>,
        hint: RecordHint,
    ) -> StatusMessage {
        StatusMessage::Ok
    }

    pub async fn read_data(vault_path: Vec<u8>, record_counter: Option<usize>) -> (Option<Vec<u8>>, StatusMessage) {
        unimplemented!()
    }

    pub async fn delete_data(vault_path: Vec<u8>, record_counter: usize, should_gc: bool) -> StatusMessage {
        unimplemented!()
    }

    pub async fn garbage_collect(vault_path: Vec<u8>, record_counter: usize) -> StatusMessage {
        unimplemented!()
    }

    pub async fn kill_stronghold(client_path: Vec<u8>, kill_actor: bool, write_snapshot: bool) -> StatusMessage {
        unimplemented!()
    }

    pub async fn list_hints_and_ids(vault_path: Vec<u8>) -> (Vec<(Vec<u8>, RecordHint)>, StatusMessage) {
        unimplemented!()
    }

    pub async fn runtime_exec(control_request: Procedure) -> StatusMessage {
        unimplemented!()
    }

    pub async fn read_snapshot(
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        new_stronghold: bool,
        options: Option<Vec<StrongholdFlags>>,
    ) -> StatusMessage {
        unimplemented!()
    }

    pub async fn write_snapshot(client_path: Vec<u8>, duration: Option<Duration>) -> StatusMessage {
        unimplemented!()
    }

    fn add_client(&mut self, keydata: Vec<u8>, client_path: Vec<u8>) {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());

        if self.clients.contains(&client_id) {
            self.current_target = Some(client_id);
        } else {
            self.clients.push(client_id);
            self.current_target = Some(client_id);

            self.data.insert(client_id, keydata);
        }
    }

    fn remove_client(&mut self, keydata: Vec<u8>, client_path: Vec<u8>) {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());
        let clients = self.clients.clone();

        let new_clients: Vec<ClientId> = clients.into_iter().filter(|id| id != &client_id).collect();

        self.data.remove(&client_id);

        self.clients = new_clients;
    }
}

#[cfg(test)]
mod tests {
    use riker::actors::*;

    use super::*;

    #[test]
    fn test_stronghold() {
        let sys = ActorSystem::new().unwrap();

        let mut stronghold = Stronghold::init_stronghold(sys);

        stronghold.add_client(b"test".to_vec(), b"path".to_vec());
        stronghold.add_client(b"test".to_vec(), b"path".to_vec());

        println!("{:?}", stronghold.clients);

        stronghold.remove_client(b"test".to_vec(), b"path".to_vec());

        println!("{:?}", stronghold.clients);
    }
}

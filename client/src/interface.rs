// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::ActorSystem;

use std::time::Duration;

use engine::vault::RecordHint;

use crate::{client::Procedure, ids::ClientId};

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
    system: ActorSystem,
}

pub struct Interface {
    stronghold: Stronghold,
    clients: Vec<ClientId>,
}

impl Stronghold {
    pub fn new(system: ActorSystem) -> Self {
        Self { system }
    }

    pub async fn start_stronghold(
        &mut self,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> (ActorSystem, StatusMessage) {
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
}

#[cfg(test)]
mod tests {
    use riker::actors::*;

    use super::*;

    #[test]
    fn test_stronghold() {
        let sys = ActorSystem::new().unwrap();

        let mut stronghold = Stronghold::new(sys);
    }
}

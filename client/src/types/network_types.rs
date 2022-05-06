// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{procedures::StrongholdProcedure, ClientError, Location, Stronghold};
use std::{any::Any, future::Future, ops::Deref, pin::Pin, time::Duration};

/// Request trait to be implemented by request messages. Each message defines
/// a distinct return type.
pub trait Request {
    type Response;

    fn inner(self) -> Box<dyn Any>;

    fn counter(&self) -> usize;
}

pub struct CheckVault {
    pub vault_path: Vec<u8>,
    pub counter: usize,
}

impl Request for CheckVault {
    type Response = bool;

    fn inner(self) -> Box<dyn Any> {
        Box::new(self)
    }

    fn counter(&self) -> usize {
        self.counter
    }
}

pub struct CheckRecord {
    location: Location,
}

pub struct WriteToRemoteVault {
    location: Location,
    payload: Vec<u8>,
}

pub struct WriteToVault {
    location: Location,
    payload: Vec<u8>,
}

pub struct RevokeData {
    location: Location,
}
pub struct DeleteData {
    location: Location,
}
pub struct ReadFromStore {
    key: Vec<u8>,
}
pub struct WriteToStore {
    key: Vec<u8>,
    payload: Vec<u8>,
    lifetime: Option<Duration>,
}
pub struct DeleteFromStore {
    key: Vec<u8>,
}
pub struct Procedures {
    procedures: Vec<StrongholdProcedure>,
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     /// FIXME: remove this test, as it does not test anything but showcases the new api
//     #[tokio::test]
//     async fn send_check_vault() {
//         let check_vault = CheckVault {
//             vault_path: b"vault-path".to_vec(),
//             counter: 0,
//         };

//         let stronghold = Stronghold::default();
//         let result = stronghold.send_request(None, b"client-path", check_vault).await;
//     }
// }

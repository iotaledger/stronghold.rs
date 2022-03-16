// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{error::Error, sync::Arc};

use crate::{Store, Vault};

pub struct Client {
    store: Option<Arc<Store>>,
    vault: Option<Arc<Vault>>,
}

impl Default for Client {
    fn default() -> Self {
        todo!()
    }
}

impl Client {
    pub async fn store(&self) -> Store {
        todo!()
    }

    pub async fn vault<P>(&self, path: P) -> Vault
    where
        P: AsRef<Vec<u8>>,
    {
        todo!()
    }

    /// Returns ok, if a vault exists
    pub async fn check_vault(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    /// Returns Ok, if the record exists
    pub async fn check_record(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

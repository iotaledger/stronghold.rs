// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::Provider;
use engine::vault::{DbView, VaultId};
use std::sync::{Arc, RwLock};

/// Thin layer over the [`DbView`]
pub struct View {
    // A view on the vault entries
    pub(crate) db: Arc<RwLock<DbView<Provider>>>,
}

impl View {
    /// Checks the internal view, if a vault by id exists
    fn exists(&self, vault_id: VaultId) -> bool {
        todo!()
    }
}

// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::macs::hmac::HMAC_SHA512;

use engine::vault::{ClientId, Id, RecordId, VaultId};

use std::convert::TryInto;

pub trait LoadFromPath: Sized {
    /// Load from some data and a path.
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self>;
}

impl LoadFromPath for Id {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);

        let (id, _) = buf.split_at(24);

        Ok(id.try_into()?)
    }
}

impl LoadFromPath for RecordId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);

        let (id, _) = buf.split_at(24);

        Ok(id.try_into()?)
    }
}

impl LoadFromPath for VaultId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        Ok(VaultId(Id::load_from_path(data, path)?))
    }
}

impl LoadFromPath for ClientId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        Ok(ClientId(Id::load_from_path(data, path)?))
    }
}

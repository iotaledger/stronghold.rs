// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::macs::hmac::HMAC_SHA512;

use engine::vault::{ClientId, Id, RecordId, VaultId};

/// A trait that allows a datatype to load and setup its internal data through the use of a path and some data.
pub trait LoadFromPath: Sized {
    /// Load from some data and a path.
    fn load_from_path(data: &[u8], path: &[u8]) -> Self;
}

/// [`LoadFromPath`] trait for [`Id`]
impl LoadFromPath for Id {
    fn load_from_path(data: &[u8], path: &[u8]) -> Self {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);
        let (id, _) = buf.split_at(24);

        id.try_into().expect("Conversion can never fail.")
    }
}

/// [`LoadFromPath`] trait for [`RecordId`]
impl LoadFromPath for RecordId {
    fn load_from_path(data: &[u8], path: &[u8]) -> Self {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);
        let (id, _) = buf.split_at(24);

        id.try_into().expect("Conversion can never fail.")
    }
}

/// [`LoadFromPath`] trait for [`VaultId`]
impl LoadFromPath for VaultId {
    fn load_from_path(data: &[u8], path: &[u8]) -> Self {
        VaultId(Id::load_from_path(data, path))
    }
}

/// [`LoadFromPath`] trait for [`ClientId`]
impl LoadFromPath for ClientId {
    fn load_from_path(data: &[u8], path: &[u8]) -> Self {
        ClientId(Id::load_from_path(data, path))
    }
}

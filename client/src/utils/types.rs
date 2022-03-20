// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{RecordId, VaultId};
use serde::{Deserialize, Serialize};

use super::LoadFromPath;

/// A `Location` type used to specify where in the `Stronghold` a piece of data should be stored. A generic location
/// specifies a non-versioned location while a counter location specifies a versioned location. The Counter location can
/// be used to get the head of the version chain by passing in `None` as the counter index. Otherwise, counter records
/// are referenced through their associated index.  On Read, the `None` location is the latest record in the version
/// chain while on Write, the `None` location is the next record in the version chain.
///
/// **Note: For each used vault an encryption key is created and protected through the [libsodium](https://doc.libsodium.org/memory_management)
/// memory protection API. Many systems place limits on the amount of memory that may be locked by a process, which may
/// result in the system panicking if the upper bound is reached!
/// For users that write a large number of secrets into Stronghold, we strongly advise against writing each record in a
/// separate vault, but instead group them into a limited number of different vaults.**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Location {
    Generic { vault_path: Vec<u8>, record_path: Vec<u8> },
    Counter { vault_path: Vec<u8>, counter: usize },
}

impl Location {
    /// Gets the vault_path from the Location.
    pub fn vault_path(&self) -> &[u8] {
        match self {
            Self::Generic { vault_path, .. } => vault_path,
            Self::Counter { vault_path, .. } => vault_path,
        }
    }

    /// Creates a generic location from types that implement [`Into<Vec<u8>>`].
    pub fn generic<V: Into<Vec<u8>>, R: Into<Vec<u8>>>(vault_path: V, record_path: R) -> Self {
        Self::Generic {
            vault_path: vault_path.into(),
            record_path: record_path.into(),
        }
    }

    /// Creates a counter location from a type that implements [`Into<Vec<u8>>`] and a counter type that implements
    /// [`Into<usize>`]
    pub fn counter<V: Into<Vec<u8>>, C: Into<usize>>(vault_path: V, counter: C) -> Self {
        Self::Counter {
            vault_path: vault_path.into(),
            counter: counter.into(),
        }
    }

    pub(crate) fn resolve(&self) -> (VaultId, RecordId) {
        match self {
            Location::Generic {
                vault_path,
                record_path,
            } => {
                let vid = derive_vault_id(vault_path);
                let rid = RecordId::load_from_path(vid.as_ref(), record_path);
                (vid, rid)
            }
            Location::Counter { vault_path, counter } => {
                let vid = derive_vault_id(vault_path);
                let rid = derive_record_id(vault_path, *counter);

                (vid, rid)
            }
        }
    }

    /// Used to generate a constant generic location.
    pub const fn const_generic(vault_path: Vec<u8>, record_path: Vec<u8>) -> Self {
        Self::Generic {
            vault_path,
            record_path,
        }
    }

    /// used to generate a constant counter location.
    pub const fn const_counter(vault_path: Vec<u8>, counter: usize) -> Self {
        Self::Counter { vault_path, counter }
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

/// Gets the [`VaultId`] from a specified path.
pub fn derive_vault_id<P: AsRef<Vec<u8>>>(path: P) -> VaultId {
    VaultId::load_from_path(path.as_ref(), path.as_ref())
}

/// Derives the counter [`RecordId`] from the given vault path and the counter value.
pub fn derive_record_id<P: AsRef<Vec<u8>>>(vault_path: P, ctr: usize) -> RecordId {
    let vault_path = vault_path.as_ref();

    let path = if ctr == 0 {
        format!("{:?}{}", vault_path, "first_record")
    } else {
        format!("{:?}{}", vault_path, ctr)
    };

    RecordId::load_from_path(path.as_bytes(), path.as_bytes())
}

/// Gets the current index of a record if its a counter.
pub fn get_index_from_record_id<P: AsRef<Vec<u8>>>(vault_path: P, record_id: RecordId) -> usize {
    let mut ctr = 0;
    let vault_path = vault_path.as_ref();

    while ctr <= 32_000_000 {
        let rid = derive_record_id(vault_path, ctr);
        if record_id == rid {
            break;
        }
        ctr += 1;
    }

    ctr
}

/// Policy options for modifying an entire Stronghold.  Must be specified on creation.
///
/// note:
/// This is deprecated.
#[derive(Clone, Debug)]
pub enum StrongholdFlags {
    IsReadable(bool),
}

/// Policy options for for a specific vault.  Must be specified on creation.
#[derive(Clone, Debug)]
pub enum VaultFlags {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rid_internals() {
        let vault_path = b"some_vault".to_vec();
        let mut ctr = 0;
        let mut ctr2 = 0;

        let _rid = derive_record_id(vault_path.clone(), ctr);
        let _rid2 = derive_record_id(vault_path.clone(), ctr2);

        ctr += 1;
        ctr2 += 1;

        let _rid = derive_record_id(vault_path.clone(), ctr);
        let _rid2 = derive_record_id(vault_path.clone(), ctr2);

        ctr += 1;

        let rid = derive_record_id(vault_path.clone(), ctr);

        let test_rid = derive_record_id(vault_path.clone(), 2);
        let ctr = get_index_from_record_id(vault_path, rid);

        assert_eq!(test_rid, rid);
        assert_eq!(2, ctr);
    }

    #[test]
    fn test_location_counter_api() {
        let vidlochead = Location::counter::<_, usize>("some_vault", 0);
        let vidlochead2 = Location::counter::<_, usize>("some_vault 2", 0);

        let (_, rid) = vidlochead.resolve();
        let (_, rid2) = vidlochead2.resolve();

        let (_, rid_head) = vidlochead.resolve();
        let (_, rid_head_2) = vidlochead2.resolve();

        assert_eq!(rid, rid_head);
        assert_eq!(rid2, rid_head_2);
    }
}

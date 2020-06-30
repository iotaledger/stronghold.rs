mod encrypt;

use crate::utils::{base32_decode, base32_encode};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox::Nonce;

#[derive(Clone)]
pub struct SnapshotStore {
    nonce: Nonce,
    payload: Vec<u8>,
    accessors: Vec<Accessor>,
}

#[derive(Clone)]
struct Accessor {
    id: String,
    enc_box: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SnapshotFileFormat {
    nonce: String,
    payload: String,
    accessors: Vec<AccessorFileFormat>,
}

#[derive(Serialize, Deserialize)]
struct AccessorFileFormat {
    id: String,
    enc_box: String,
}

impl SnapshotFileFormat {
    fn new(store: SnapshotStore) -> Self {
        Self {
            nonce: base32_encode(&store.nonce.0),
            payload: base32_encode(&store.payload),
            accessors: store
                .accessors
                .into_iter()
                .map(|access| AccessorFileFormat::new(access))
                .collect(),
        }
    }

    fn into_snapshot_store(self) -> Option<SnapshotStore> {
        Some(SnapshotStore {
            nonce: Nonce::from_slice(&base32_decode(&self.nonce)?)?,
            payload: base32_decode(&self.payload)?,
            accessors: self
                .accessors
                .into_iter()
                .map(|access| access.into_accessors())
                .collect::<Option<Vec<Accessor>>>()?,
        })
    }
}

impl AccessorFileFormat {
    fn new(accessor: Accessor) -> Self {
        Self {
            id: accessor.id,
            enc_box: base32_encode(&accessor.enc_box),
        }
    }

    fn into_accessors(self) -> Option<Accessor> {
        Some(Accessor {
            id: self.id,
            enc_box: base32_decode(&self.enc_box)?,
        })
    }
}

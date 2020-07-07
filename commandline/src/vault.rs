use std::collections::HashMap;
use vault::{
    Base64Decodable, Base64Encodable, IndexHint, Key, ListResult, ReadRequest, ReadResult,
};

use super::provider::Provider;
use crate::error_line;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub key: Key<Provider>,
    pub entries: HashMap<Vec<u8>, Vec<u8>>,
}

impl Vault {
    pub fn new(key: Key<Provider>) -> Self {
        Self {
            key,
            entries: HashMap::new(),
        }
    }

    pub fn list(&self) -> ListResult {
        ListResult::new(self.entries.keys().cloned().collect())
    }

    pub fn read(&self, req: ReadRequest) -> Option<ReadResult> {
        let id = req.into();

        self.entries
            .get(&id)
            .map(|data| ReadResult::new(id, data.clone()))
    }

    pub fn key(&self) -> &Key<Provider> {
        &self.key
    }

    pub fn dump_data(&self) -> Vec<u8> {
        let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
        encoded
    }

    pub fn load_data(&self, input: Vec<u8>) -> Self {
        let vault: Vault = bincode::deserialize(&input).unwrap();

        vault
    }
}

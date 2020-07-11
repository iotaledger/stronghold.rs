use std::collections::HashMap;
use vault::{
    Base64Decodable, Base64Encodable, Key, ListResult, ReadRequest, ReadResult, RecordHint,
};

use super::provider::Provider;
use crate::error_line;

pub struct TestVault {
    pub key: Key<Provider>,
    pub entries: HashMap<Vec<u8>, Vec<u8>>,
}

pub struct PlainVault {
    pub entries: HashMap<RecordHint, Vec<u8>>,
}

impl TestVault {
    #[allow(unused)]
    pub fn empty(key: Key<Provider>) -> Self {
        Self {
            key,
            entries: HashMap::new(),
        }
    }

    pub fn from_json(data: &str, name: &str) -> Self {
        let db = json::parse(data).expect(error_line!("Invalid JSON document"));
        assert!(
            db["storage"][name].is_array(),
            error_line!("No `storage`-array for the requested name")
        );

        let key = db["key"]
            .as_str()
            .expect(error_line!("Missing key in JSON document"));
        let key = Vec::from_base64(key).expect(error_line!("Invalid base64 `key` field"));
        let key = Key::load(key).expect(error_line!("Invalid data in `key` field"));

        let mut entries = HashMap::new();
        for entry in db["storage"][name].members() {
            let name = entry["name"]
                .as_str()
                .expect(error_line!("Missing `name` field"));
            let data = entry["data"]
                .as_str()
                .expect(error_line!("Missing `data` field"));

            let name = Vec::from_base64(name).expect(error_line!("Invalid base64 `name` field"));
            let data = Vec::from_base64(data).expect(error_line!("Invalid base64 `data` field"));
            entries.insert(name, data);
        }
        Self { key, entries }
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

    #[allow(unused)]
    pub fn dump_json(&self) -> String {
        let mut array = json::Array::new();
        self.entries.iter().for_each(|(name, data)| {
            array.push(json::object! {
                "name" => name.base64(),
                "data" => data.base64()
            })
        });
        json::stringify_pretty(array, 2)
    }
}

impl PlainVault {
    #[allow(unused)]
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
    pub fn from_json(data: &str, name: &str) -> Self {
        let db = json::parse(data).expect(error_line!("Invalid JSON document"));
        assert!(
            db["plain"][name].is_array(),
            error_line!("No array for the requested name")
        );

        let mut entries = HashMap::new();
        for entry in db["plain"][name].members() {
            let hint = entry["hint"]
                .as_str()
                .expect(error_line!("Missing `hint` field"));
            let data = entry["data"]
                .as_str()
                .expect(error_line!("Missing `data` field"));

            let hint = Vec::from_base64(hint).expect(error_line!("Invalid base64 `hint` field"));
            let data = Vec::from_base64(data).expect(error_line!("Invalid base64 `data` field"));

            let hint =
                RecordHint::new(&hint).expect(error_line!("Invalid data in `RecordHint` field"));
            entries.insert(hint, data);
        }
        Self { entries }
    }
    #[allow(unused)]
    pub fn dump_json(&self) -> String {
        let mut array = json::Array::new();
        self.entries.iter().for_each(|(hint, data)| {
            array.push(json::object! {
                "hint" => hint.base64(),
                "data" => data.base64()
            })
        });
        json::stringify_pretty(array, 2)
    }
}

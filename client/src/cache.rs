use std::{collections::HashMap, fmt::Debug};

use dashmap::DashMap;
use engine::vault::{DeleteRequest, Kind, ReadRequest, ReadResult, WriteRequest};

use zeroize_derive::Zeroize;

use crate::{
    line_error,
    secret::{CloneSecret, ReadSecret, Secret},
};

#[derive(Clone, Debug, Zeroize)]
pub struct Value<T>(T);

impl<T> Value<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }
}

pub struct Cache {
    table: DashMap<Vec<u8>, Value<Secret<Vec<u8>>>>,
}

#[derive(Clone)]
pub enum CRequest {
    List,
    Write(WriteRequest),
    Delete(DeleteRequest),
    Read(ReadRequest),
}

#[derive(Clone)]
pub enum CResult {
    List,
    Write,
    Delete,
    Read(ReadResult),
}

impl Cache {
    pub fn new() -> Self {
        Cache { table: DashMap::new() }
    }

    fn add_data(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.table.insert(key, Value::new(Secret::new(value)));
    }

    fn read_data(&self, key: Vec<u8>) -> Value<Secret<Vec<u8>>> {
        self.table.get(&key).expect(line_error!()).clone()
    }

    pub fn offload_data(self) -> HashMap<Vec<u8>, Vec<u8>> {
        let mut ret: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

        self.table.into_iter().for_each(|(k, v)| {
            ret.insert(k, v.0.read_secret().to_vec());
        });

        ret
    }

    pub fn upload_data(&self, map: HashMap<Vec<u8>, Vec<u8>>) {
        map.into_iter().for_each(|(k, v)| {
            self.table.insert(k, Value::new(Secret::new(v)));
        });
    }

    pub fn send(&mut self, req: CRequest) -> CResult {
        let result = match req {
            CRequest::List => CResult::List,
            CRequest::Write(write) => {
                self.add_data(write.id().to_vec(), write.data().to_vec());
                CResult::Write
            }
            CRequest::Delete(del) => {
                self.table.retain(|id, _| *id != del.id());
                CResult::Delete
            }
            CRequest::Read(read) => {
                let state = self.read_data(read.id().to_vec());
                CResult::Read(ReadResult::new(
                    Kind::Transaction,
                    read.id(),
                    &state.0.read_secret().to_vec(),
                ))
            }
        };
        result
    }
}

impl CloneSecret for Vec<u8> {}

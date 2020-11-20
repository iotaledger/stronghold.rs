use std::{collections::HashMap, fmt::Debug};

use engine::vault::{DeleteRequest, ReadRequest, ReadResult, WriteRequest};

use crate::{ids::VaultId, line_error, secret::CloneSecret};

pub struct Cache {
    table: HashMap<VaultId, Vec<ReadResult>>,
}

#[derive(Clone)]
pub enum CRequest {
    List(VaultId),
    Write((VaultId, WriteRequest)),
    Delete((VaultId, WriteRequest)),
    Read((VaultId, ReadRequest)),
}

#[derive(Clone)]
pub enum CResult {
    List(Vec<ReadResult>),
    Write,
    Delete,
    Read(ReadResult),
}

impl Cache {
    pub fn new() -> Self {
        Cache { table: HashMap::new() }
    }

    pub fn add_data(&mut self, key: VaultId, value: ReadResult) {
        let mut vec = self.table.remove(&key).expect(line_error!());

        vec.push(value);

        self.table.insert(key, vec);
    }

    pub fn read_data(&self, key: VaultId, id: Vec<u8>) -> ReadResult {
        let vec = self.table.get(&key).expect(line_error!());

        let mut res: Vec<ReadResult> = vec.clone().into_iter().filter(|val| val.id().to_vec() == id).collect();

        res.pop().expect(line_error!())
    }

    pub fn offload_data(self) -> HashMap<VaultId, Vec<ReadResult>> {
        let mut ret: HashMap<VaultId, Vec<ReadResult>> = HashMap::new();

        self.table.into_iter().for_each(|(k, v)| {
            ret.insert(k, v);
        });

        ret
    }

    pub fn upload_data(&mut self, map: HashMap<VaultId, Vec<ReadResult>>) {
        map.into_iter().for_each(|(k, v)| {
            self.table.insert(k, v);
        });
    }

    pub fn send(&mut self, req: CRequest) -> CResult {
        let result = match req {
            CRequest::List(id) => {
                let res = self.table.entry(id).or_insert(vec![]);

                CResult::List(res.to_vec())
            }
            CRequest::Write((id, write)) => {
                self.add_data(id, write_to_read(&write));
                CResult::Write
            }
            CRequest::Delete((id, delete)) => {
                let vec = self.table.remove(&id).expect(line_error!());

                let vec = vec.into_iter().filter(|x| x.id() != delete.id()).collect();

                self.table.insert(id, vec);

                CResult::Delete
            }
            CRequest::Read(read) => unimplemented!(),
        };
        result
    }
}

impl CResult {
    pub fn list(self) -> Vec<ReadResult> {
        match self {
            CResult::List(readreq) => readreq,
            _ => panic!(line_error!()),
        }
    }
}

impl CloneSecret for Vec<u8> {}

pub fn write_to_read(write: &WriteRequest) -> ReadResult {
    ReadResult::new(write.kind(), write.id(), write.data())
}

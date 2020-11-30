// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{DeleteRequest, ReadRequest, ReadResult, WriteRequest, Kind};

use std::{thread, time::Duration};

use crate::{line_error, state::State};

// requests to the vault.
#[derive(Clone)]
pub enum CRequest {
    List,
    Write(WriteRequest),
    Delete(DeleteRequest),
    Read(ReadRequest),
}

// results from the vault.
#[derive(Clone)]
pub enum CResult {
    List(Vec<ReadResult>),
    Write,
    Delete,
    Read(ReadResult),
}

impl CResult {
    // get a list result back.
    pub fn list(self) -> Vec<ReadResult> {
        match self {
            CResult::List(list) => list,
            _ => panic!(line_error!()),
        }
    }
}

// resolve the requests into responses.
pub fn send(req: CRequest) -> Option<CResult> {
    let result = match req {
        // if the request is a list, get the keys from the map and put them into a ListResult.
        CRequest::List => {
            let entries = State::storage_map()
                .read().expect(line_error!())
                .iter()
                .filter_map(|((k, id), bs)|
                    if *k == Kind::Transaction {
                        Some(ReadResult::new(*k, id, bs))
                    } else {
                        None
                    }
                )
                .collect();
            CResult::List(entries)
        }
        // on write, write data to the map and send back a Write result.
        CRequest::Write(write) => {
            State::storage_map()
                .write()
                .expect(line_error!())
                .insert((write.kind(), write.id().to_vec()), write.data().to_vec());

            CResult::Write
        }
        // on delete, delete data from the map and send back a Delete result.
        CRequest::Delete(del) => {
            State::storage_map()
                .write()
                .expect(line_error!())
                .retain(|id, _| id.0 != del.kind() || id.1 != del.id());

            CResult::Delete
        }
        // on read, read the data from the map and send it back in a Read Result.
        CRequest::Read(read) => {
            let bs = State::storage_map()
                .read()
                .expect(line_error!())
                .get(&(read.kind(), read.id().to_vec()))
                .cloned()
                .expect(line_error!());

            CResult::Read(read.result(bs))
        }
    };

    Some(result)
}

// Loop until there is a Result.
pub fn send_until_success(req: CRequest) -> CResult {
    loop {
        match send(req.clone()) {
            Some(result) => {
                break result;
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

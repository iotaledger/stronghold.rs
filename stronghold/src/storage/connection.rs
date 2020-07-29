use engine::{vault};

use vault::{DeleteRequest, ListResult, ReadRequest, ReadResult, WriteRequest};

use std::{thread, time::Duration};

use super::state::State;

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
    List(ListResult),
    Write,
    Delete,
    Read(ReadResult),
}

impl CResult {
    // get a list result back.
    pub fn list(self) -> ListResult {
        match self {
            CResult::List(list) => list,
            _ => panic!(line_error!()),
        }
    }
}

// resolve the requests into responses.
pub fn send(req: CRequest) -> CResult {
    let result = match req {
        // if the request is a list, get the keys from the map and put them into a ListResult.
        CRequest::List => {
            let entries = State::storage_map()
                .read()
                .expect(line_error!())
                .keys()
                .cloned()
                .collect();

            CResult::List(ListResult::new(entries))
        }
        // on write, write data to the map and send back a Write result.
        CRequest::Write(write) => {
            State::storage_map()
                .write()
                .expect(line_error!())
                .insert(write.id().to_vec(), write.data().to_vec());

            CResult::Write
        }
        // on delete, delete data from the map and send back a Delete result.
        CRequest::Delete(del) => {
            State::storage_map()
                .write()
                .expect(line_error!())
                .retain(|id, _| *id != del.id());

            CResult::Delete
        }
        // on read, read the data from the map and send it back in a Read Result.
        CRequest::Read(read) => {
            let state = State::storage_map()
                .read()
                .expect(line_error!())
                .get(read.id())
                .cloned()
                .expect(line_error!());

            CResult::Read(ReadResult::new(read.into(), state))
        }
    };

    result
}
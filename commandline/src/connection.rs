use vault::{DeleteRequest, ListResult, WriteRequest};

use std::{thread, time::Duration};

use crate::line_error;
use crate::state::State;

#[derive(Clone)]
pub enum CRequest {
    List,
    Write(WriteRequest),
    Delete(DeleteRequest),
}

#[derive(Clone)]
pub enum CResult {
    List(ListResult),
    Write,
    Delete,
}

impl CResult {
    pub fn list(self) -> ListResult {
        match self {
            CResult::List(list) => list,
            _ => panic!(line_error!()),
        }
    }
}

pub fn send(req: CRequest) -> Option<CResult> {
    let result = match req {
        CRequest::List => {
            let entries = State::backup_map()
                .read()
                .expect(line_error!())
                .keys()
                .cloned()
                .collect();
            CResult::List(ListResult::new(entries))
        }
        CRequest::Write(write) => {
            State::backup_map()
                .write()
                .expect(line_error!())
                .insert(write.id().to_vec(), write.data().to_vec());

            CResult::Write
        }
        CRequest::Delete(del) => {
            State::backup_map()
                .write()
                .expect(line_error!())
                .remove(del.id());

            CResult::Delete
        }
    };

    Some(result)
}

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

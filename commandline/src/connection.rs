use vault::{DeleteRequest, ListResult, WriteRequest};

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
            let entries = State::storage_channel().keys().cloned().collect();
            CResult::List(ListResult::new(entries))
        }
        CRequest::Write(write) => {
            State::storage_channel()
                .insert(write.id().to_vec(), write.data().to_vec())
                .unwrap();

            CResult::Write
        }
        CRequest::Delete(del) => {
            State::storage_channel().remove(del.id());

            CResult::Delete
        }
    };

    Some(result)
}

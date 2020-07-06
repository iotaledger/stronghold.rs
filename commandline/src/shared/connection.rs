use crate::shared::env::Env;

use vault::{DeleteRequest, ListResult, WriteRequest};

use std::{thread, time::Duration};

#[derive(Clone)]
pub enum TransactionRequest {
    List,
    Write(WriteRequest),
    Delete(DeleteRequest),
}

#[derive(Clone)]
pub enum TransactionResult {
    List(ListResult),
    Write,
    Delete,
}

impl TransactionResult {
    pub fn list(self) -> ListResult {
        match self {
            TransactionResult::List(list) => list,
            _ => panic!(line_error!()),
        }
    }
}

fn send(req: TransactionRequest) -> Option<TransactionResult> {
    let res = match req {
        TransactionRequest::List => {
            let entries = Env::get_storage()
                .read()
                .expect(line_error!())
                .keys()
                .cloned()
                .collect();

            TransactionResult::List(ListResult::new(entries))
        }
        TransactionRequest::Write(write) => {
            Env::get_storage()
                .write()
                .expect(line_error!())
                .insert(write.id().to_vec(), write.data().to_vec());

            TransactionResult::Write
        }
        TransactionRequest::Delete(delete) => {
            Env::get_storage()
                .write()
                .expect(line_error!())
                .remove(delete.id());
            TransactionResult::Delete
        }
    };

    Some(res)
}

pub fn send_until_success(req: TransactionRequest) -> TransactionResult {
    loop {
        match send(req.clone()) {
            Some(result) => break result,
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

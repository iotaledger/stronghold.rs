// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{crypt::CRng, env::Env};

use vault::{DeleteRequest, ListResult, WriteRequest};

use std::{thread, time::Duration};

// vault request
#[derive(Clone)]
pub enum TransactionRequest {
    List,
    Write(WriteRequest),
    Delete(DeleteRequest),
}

// vault result
#[derive(Clone)]
pub enum TransactionResult {
    List(ListResult),
    Write,
    Delete,
}

impl TransactionResult {
    // return a list of results
    pub fn list(self) -> ListResult {
        match self {
            TransactionResult::List(list) => list,
            _ => panic!(line_error!()),
        }
    }
}

// send a message
fn send(req: TransactionRequest) -> Option<TransactionResult> {
    // should request fail or not
    if CRng::bool(Env::error_rate()) {
        None?
    }

    let res = match req {
        TransactionRequest::List => {
            let records = Env::storage()
                .read()
                .expect(line_error!())
                .keys()
                .cloned()
                .collect();

            TransactionResult::List(ListResult::new(records))
        }
        TransactionRequest::Write(write) => {
            Env::storage()
                .write()
                .expect(line_error!())
                .insert(write.id().to_vec(), write.data().to_vec());
            TransactionResult::Write
        }
        TransactionRequest::Delete(delete) => {
            Env::storage()
                .write()
                .expect(line_error!())
                .remove(delete.id());
            TransactionResult::Delete
        }
    };

    // should result fail or not
    match CRng::bool(Env::error_rate()) {
        false => Some(res),
        true => None,
    }
}

// send a request until there is a response - emulates network
pub fn send_until_success(req: TransactionRequest) -> TransactionResult {
    loop {
        match send(req.clone()) {
            Some(result) => break result,
            None => thread::sleep(Duration::from_millis(Env::retry_delay())),
        }
    }
}

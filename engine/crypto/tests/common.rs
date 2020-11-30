// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use hex::decode;
use json::{iterators::Members, JsonValue};

// extension for JsonValue
pub trait JsonValueExt {
    // decode string
    fn check_string(&self) -> String;
    // hex-decode string into byte vector
    fn check_bytes(&self) -> Vec<u8>;
    // check if null
    fn check_array_iter(&self) -> Members;
    // get usize if not null
    fn option_usize(&self, def: usize) -> usize;
    // get string if not null
    fn option_string(&self, def: impl ToString) -> String;
}

impl JsonValueExt for JsonValue {
    fn check_string(&self) -> String {
        self.as_str().unwrap().to_string()
    }

    fn check_bytes(&self) -> Vec<u8> {
        let encode = self.as_str().unwrap();

        decode(encode).unwrap()
    }

    fn check_array_iter(&self) -> Members {
        assert!(self.is_array());
        self.members()
    }
    fn option_usize(&self, def: usize) -> usize {
        if self.is_number() {
            self.as_usize().unwrap()
        } else {
            def
        }
    }
    fn option_string(&self, def: impl ToString) -> String {
        if self.is_string() {
            self.as_str().unwrap().to_string()
        } else {
            def.to_string()
        }
    }
}

// result extension
pub trait ResultExt<T, E> {
    // unwraps error and panics
    fn error_or(self, msg: impl ToString) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn error_or(self, msg: impl ToString) -> E {
        match self {
            Err(e) => e,
            _ => panic!(msg.to_string()),
        }
    }
}

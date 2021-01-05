// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub mod cache;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Value<T> {
    pub val: T,
    expiration: Option<SystemTime>,
}

impl<T> Value<T> {
    pub fn new(val: T, duration: Option<Duration>) -> Self {
        Value {
            val,
            expiration: duration.map(|d| SystemTime::now() + d),
        }
    }

    pub fn has_expired(&self, time_now: SystemTime) -> bool {
        self.expiration.map_or(false, |time| time_now >= time)
    }
}

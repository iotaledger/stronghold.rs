// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub mod cache;

/// The general value used for the [`Store`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Value<T> {
    // data field.
    pub val: T,
    // expiration time.
    expiration: Option<SystemTime>,
}

impl<T> Value<T> {
    /// Create a new [`Value`] with a specified expiration.
    pub fn new(val: T, duration: Option<Duration>) -> Self {
        Value {
            val,
            expiration: duration.map(|d| SystemTime::now() + d),
        }
    }

    /// Checks to see if the [`Value`] has expired.
    pub fn has_expired(&self, time_now: SystemTime) -> bool {
        self.expiration.map_or(false, |time| time_now >= time)
    }
}

// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use stronghold_utils::{random::*, test_utils};

use crate::Location;

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(bytestring(4096), bytestring(4096))
}
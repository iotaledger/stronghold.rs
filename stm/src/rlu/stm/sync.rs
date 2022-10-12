// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// #[cfg(not(feature = "no_deadlocks"))]
// pub use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "no_deadlocks")]
pub use no_deadlocks::{Mutex, MutexGuard};

pub use std::sync::{
    atomic::{AtomicBool, AtomicIsize},
    Arc,
};

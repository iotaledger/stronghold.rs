// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # RLU Guard Types
//!
//! This module has guard types for read and writes for an [`crate::RLUObject`]. The guard
//! types follow the RAII pattern. Dropping the guards will affect the referenced object by either
//! signaling an end of read, or signaling the start of memory commit depending on the type of guard.

pub mod base;
pub mod read;
pub mod write;

pub use base::BaseGuard;
pub use read::ReadGuard;
pub use write::WriteGuard;

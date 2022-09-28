// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Client Interface
//!
//! The client interface exposes all functionality to work with a Stronghold instance

// FIXME: remove this later, when feature-complete
#![allow(unused_variables, unused_imports, dead_code)]

#[cfg(feature = "std")]
pub use crate::{internal::Provider, security::*, types::*, utils::*};

#[cfg(feature = "std")]
pub use engine::runtime::MemoryError;

#[cfg(feature = "std")]
pub(crate) use crate::sync::SnapshotHierarchy;

#[cfg(feature = "std")]
pub mod types;

#[cfg(feature = "std")]
pub mod internal;

#[cfg(feature = "std")]
pub mod security;

#[cfg(feature = "std")]
pub mod procedures;

#[cfg(feature = "std")]
pub mod sync;

// is this std?
#[cfg(feature = "std")]
pub mod utils;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;

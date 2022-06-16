// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Read-Log-Update (RLU)
//! ---
//! This module implements the read log update synchronization mechanism
//! to enable non-blocking concurrent reads and concurrent writes on
//! data.
//!
//! ## Objective
//! ---
//! RLU solves the problem with having multiple concurrent readers being non-block, while having a writer synchronizing
//! with the reads. RLU still suffers from writer-writer synchronization, eg. two writers with the same memory location
//! want to update the value.
//!
//! ## Algorithm
//! ---
//! The main idea is to allow readers non-blocking access to data. RLU employs a global clock (counter)
//! for (single) versioned updates on objects. On writes, a thread will create a copy of the target
//! object, locking it before, and conduct any modification to the object inside the log. This ensure
//! that any modification is hidden from other threads. The writing thread increments the global clock,
//! so that readers are split into two sets: the readers reading the old state, and readers reading the
//! new state from the logs of the writing thread.
//!
//! The writing thread waits until all readers have concluded their reads, then commits the changes to memory
//! and update the global clock.
//!
//! ## Features
//! ---
//! - [x] multiple readers / writers
//! - [x] lock free ( only internal locks )
//!
//! # Sources
//! - [notes](https://chaomai.github.io/2015/2015-09-26-notes-of-rlu/)
//! - [paper](https://people.csail.mit.edu/amatveev/RLU_SOSP15_paper.pdf)
//! - [reference impl](https://github.com/rlu-sync/rlu/blob/master/rlu.c)
//! - [rcu presentation](https://www.cs.unc.edu/~porter/courses/cse506/f11/slides/rcu.pdf)
#![allow(unused_variables, dead_code, clippy::type_complexity)]

pub mod breaker;
pub mod guard;
pub mod rlog;
pub mod rlu;
pub mod types;
pub mod var;

mod stm;

// public re-exports
pub use breaker::BusyBreaker;
pub use rlu::{RLUObject, RLUStrategy, Result, RluContext, TransactionError, RLU};
pub use types::{Read, Write};
pub use var::{InnerVar, RLUVar};

// crate re-exports
pub(crate) use guard::{ReadGuard, WriteGuard};
pub(crate) use rlog::RLULog;

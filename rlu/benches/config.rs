// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Transactional memory stress tests
//!
//! Test subjects:
//! - spawn a lot of futures (1000+)
//! - work with larger chunks of memory (> 10M, 100M, 1G)
//! - lots of read / write alternations
mod memory;

use criterion::{criterion_group, criterion_main};
use memory::*;

// all memory benches
criterion_group!(benches, bnc_memory_usize);

// main
criterion_main!(benches);

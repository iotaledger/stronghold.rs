// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This module provides acces to a Software Transactional Memory (STM)
//! implementation.
//!
//! An STM allows an performance execution of concurrent operations
//! on shard memory using optimisitic locking. Operations that write
//! on shared memory are using optimistic locking. That is, that each
//! write operation will not check for consistence, by will be recordered
//! each operation in a lock. If the operation is finished, and each operation
//! is considered consistent accord to the log, the operations a whole will
//! be executed as atomical transaction. Otherwise the transaction will be
//! rolled back and tried again

mod core;

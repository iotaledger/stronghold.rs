// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// read log update impl
use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicUsize, Arc, Mutex, RwLock},
};

use crate::LockedMemory;
use lazy_static::lazy_static;

pub trait Memory: LockedMemory + Send + Sync {}

lazy_static! {
    pub static ref CLOCK: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Default)]
pub struct Tx<T>
where
    T: Memory,
{
    local_clock: AtomicUsize,
    write_click: AtomicUsize,

    reads: Arc<RwLock<BTreeMap<usize, Vec<T>>>>,
    writes: Arc<RwLock<BTreeMap<usize, Vec<T>>>>,
}

pub struct TObject<T>
where
    T: Memory,
{
    /// this is a reference to a log, that are initially null
    log: Arc<Mutex<Option<T>>>,

    // this is the real memory
    real: Arc<Mutex<T>>,
}

impl<T> Tx<T>
where
    T: Memory,
{
    pub fn read(&self, obj: TObject<T>) -> T {
        todo!()
    }

    pub fn write(&self, value: T, obj: TObject<T>) {
        todo!()
    }

    fn commit(&self) {
        todo!()
    }
}

impl<T> TObject<T>
where
    T: Memory,
{
    pub fn read(&self) -> T {
        todo!()
    }

    pub fn write(&self, value: T) {
        todo!()
    }
}

#[cfg(test)]
mod tests {}

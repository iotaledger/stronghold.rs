// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Read-Log-Update (RLU)
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
//!
//! # Sources
//! - [notes](https://chaomai.github.io/2015/2015-09-26-notes-of-rlu/)
//! - [paper](https://people.csail.mit.edu/amatveev/RLU_SOSP15_paper.pdf)
//! - [reference impl](https://github.com/rlu-sync/rlu/blob/master/rlu.c)
//! - [rcu presentation](https://www.cs.unc.edu/~porter/courses/cse506/f11/slides/rcu.pdf)

#![allow(dead_code, unused_variables)]

use log::*;
use std::{
    cell::Cell,
    collections::HashMap,
    hash::Hash,
    sync::{
        atomic::{AtomicBool, AtomicIsize, AtomicPtr, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

thread_local! {
    static GUARD : Cell<bool> = Cell::new(false);
}

/// Virtual Type to use as return
pub trait ReturnType: Clone + Send + Sync + Sized {}

/// Global return type
pub type Result<T> = std::result::Result<T, TransactionError>;

/// Simplified atomic mutex
pub type ClonableMutex<T> = Arc<Mutex<T>>;

/// auto impl for return type
impl<T> ReturnType for T where T: Send + Sync + Clone + Sized {}

pub struct DataMap<K, V>
where
    K: Hash + Eq,
{
    inner: HashMap<K, V>,
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction failed")]
    Failed,

    #[error("Transaction alread running")]
    InProgress,

    #[error("Inner error occured ({0})")]
    Inner(String),
}

/// This is the global object for reading and writing
pub struct TVar<'a, T>
where
    T: ReturnType,
{
    /// the actual data
    data: Arc<AtomicPtr<T>>,

    /// a ptr to the write log copy inside an RLU thread
    copy_ptr: Arc<AtomicPtr<TVar<'a, T>>>,

    /// indicating, if this is a copy
    is_copy: Arc<AtomicBool>,

    /// the current thread locking this object
    rlu_thread_id: Arc<AtomicIsize>,

    /// if this is a copy, this is the reference to the 'original'
    obj_reference: Arc<AtomicPtr<TVar<'a, T>>>,

    /// all global related rlu objects reside here, since they are interested in synchronizing
    /// one object at a time
    global_clock: Arc<AtomicUsize>,

    /// a list of all threads monitoring this variable
    threads: Arc<AtomicPtr<HashMap<isize, &'a RLUContext<'a, T>>>>,
}

impl<'a, T> Clone for TVar<'a, T>
where
    T: ReturnType,
{
    fn clone(&self) -> Self {
        Self {
            data: Arc::new(AtomicPtr::new(self.data.load(Ordering::Acquire))), // ?

            /// TODO: self needs to be update to this
            copy_ptr: Arc::new(AtomicPtr::new(std::ptr::null_mut())),

            is_copy: Arc::new(AtomicBool::new(true)),

            rlu_thread_id: self.rlu_thread_id.clone(),

            obj_reference: Arc::new(AtomicPtr::new(&self as *const _ as *mut TVar<'a, T>)),

            global_clock: Arc::new(AtomicUsize::new(self.global_clock.load(Ordering::Acquire))),

            // the pointer to active threads can be safely cloned
            threads: self.threads.clone(),
        }
    }
}

impl<'a, T> TVar<'a, T>
where
    T: ReturnType,
{
    fn new(mut value: T) -> Self {
        Self {
            data: Arc::new(AtomicPtr::new(&mut value)),
            copy_ptr: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            is_copy: Arc::new(AtomicBool::new(false)),
            rlu_thread_id: Arc::new(AtomicIsize::new(-1)),
            obj_reference: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            global_clock: Arc::new(AtomicUsize::new(0)),
            threads: Arc::new(AtomicPtr::new(&mut HashMap::new())),
        }
    }

    fn get_rlu_context(&self, id: &isize) -> &'a RLUContext<T> {
        let threads = unsafe { &*self.threads.load(Ordering::Acquire) };
        threads.get(id).unwrap()
    }
}

pub struct RLUContext<'a, T>
where
    T: ReturnType,
{
    // the thread id
    thread_id: Arc<AtomicIsize>,

    /// first write log
    w_log: Arc<AtomicPtr<TVar<'a, T>>>,

    /// second write log
    w_log_quiescence: Arc<AtomicPtr<TVar<'a, T>>>,

    // according to the paper we need a run counter
    // where even indicates a running state, and odd
    // is a rest
    run_count: Arc<AtomicUsize>,

    /// The local clock to decide wether to read from log, or object
    local_clock: Arc<AtomicUsize>,

    /// the write clock to signal reading from
    write_clock: Arc<AtomicUsize>,

    /// sets if writer, or not. may be obsolete
    is_writer: Arc<AtomicBool>,

    /// sync counts
    sync_counts: Arc<AtomicPtr<HashMap<isize, isize>>>,
}

impl<'a, T> RLUContext<'a, T>
where
    T: ReturnType + 'a,
{
    pub fn with_func<F>(f: F) -> Result<()>
    where
        F: Fn(Self) -> Result<()>,
    {
        if GUARD.with(|inner| match inner.get() {
            true => true,
            false => {
                inner.set(true);
                false
            }
        }) {
            return Err(TransactionError::InProgress);
        }

        let tx = RLUContext {
            thread_id: Arc::new(AtomicIsize::new(-1)),
            w_log: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            w_log_quiescence: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            run_count: Arc::new(AtomicUsize::new(0)),
            local_clock: Arc::new(AtomicUsize::new(0)),
            write_clock: Arc::new(AtomicUsize::new(0)),
            is_writer: Arc::new(AtomicBool::new(false)),
            sync_counts: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
        };

        f(tx)
    }

    /// reads a snapshot of `T` and returns it
    pub fn read(&self, var: &'a T) -> &'a T {
        // self.reader_lock(var);
        // let _inner = unsafe { &*self.deref(var).data.load(Ordering::Acquire).clone() };
        // self.reader_unlock(var);

        // _inner
        todo!()
    }

    pub fn write(&self, value: T, var: &'a TVar<'a, T>) {
        self.try_lock(var);
    }

    /// --- inner API

    fn reader_lock(&self, var: &'a TVar<'a, T>) {
        // set as reader
        self.is_writer.store(false, Ordering::Release);

        // increment number of runners. odd = running, evening = rest
        // important, when synchronizing the threads
        self.run_count
            .store(self.run_count.load(Ordering::Acquire) + 1, Ordering::Release);

        // update local clock
        self.local_clock
            .store(var.global_clock.load(Ordering::Acquire), Ordering::Release)
    }

    fn reader_unlock(&self, var: &'a TVar<'a, T>) {
        // increment number of runners
        self.run_count
            .store(self.run_count.load(Ordering::Acquire) + 1, Ordering::Release);

        if self.is_writer.load(Ordering::Acquire) {
            self.commit_write_log(var)
        }
    }

    /// function marker to abort at specific point
    /// may be replace with a function return
    fn retry(&self) {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        if self.is_writer.load(Ordering::Acquire) {}

        // TODO: signal retry
    }

    /// This is `read`
    fn deref(&self, var: &'a TVar<'a, T>) -> &'a TVar<'a, T> {
        if var.is_copy.load(Ordering::Acquire) {
            return unsafe { &*var.copy_ptr.load(Ordering::Acquire) };
        }

        let copy_ptr = var.copy_ptr.load(Ordering::Acquire);

        // is unlocked
        if copy_ptr.is_null() {
            return var;
        }

        let copy_ptr = unsafe { &*copy_ptr };

        if self.thread_id.load(Ordering::Acquire) == copy_ptr.rlu_thread_id.load(Ordering::Acquire) {
            return copy_ptr;
        }

        let thread_id = copy_ptr.rlu_thread_id.load(Ordering::Acquire);

        let thread: &RLUContext<'a, T> = var.get_rlu_context(&(thread_id));

        if self.local_clock.load(Ordering::Acquire) >= thread.write_clock.load(Ordering::Acquire) {
            return copy_ptr;
        }

        var
    }

    /// This is `write`
    fn try_lock(&self, var: &'a TVar<'a, T>) -> Option<*const TVar<'a, T>> {
        // write operation
        self.is_writer.store(true, Ordering::Release);

        // get actual object
        let original_data = var.data.load(Ordering::Acquire);

        // get pointer to copy, most probably null
        let copy_ptr = var.copy_ptr.load(Ordering::Acquire);

        // is locked
        if !copy_ptr.is_null() {
            let copy_ptr = unsafe { &mut *copy_ptr };
            let thread_id = copy_ptr.rlu_thread_id.load(Ordering::Acquire);

            if self.thread_id.load(Ordering::Acquire) == thread_id {
                return Some(copy_ptr as *mut _);
            }

            // retry / abort
            self.retry();

            // indicate retry
            return None;
        }

        let mut copy = var.clone();

        copy.obj_reference
            .store(var as *const _ as *mut TVar<'a, T>, Ordering::Release);

        let self_thread_id = self.thread_id.load(Ordering::Acquire);
        var.rlu_thread_id.store(self_thread_id as isize, Ordering::Release);

        //
        self.w_log.store(&mut copy, Ordering::Release);

        if var
            .copy_ptr
            .compare_exchange(std::ptr::null_mut(), &mut copy, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.retry()
        }

        Some(&copy as *const _)
    }

    fn commit_write_log(&self, var: &'a TVar<'a, T>) {
        self.write_clock
            .store(var.global_clock.load(Ordering::Acquire) + 1, Ordering::Release);

        var.global_clock.fetch_add(1, Ordering::SeqCst);

        self.synchronize(var);

        // - write back write log
        // - unlock write lock
        self.write_clock.store(usize::MAX, Ordering::Release);

        // - swap write logs
        self.swap_write_logs();
    }

    /// block this thread, until all other reading threads have finished
    fn synchronize(&self, var: &'a TVar<'a, T>) {
        let threads = unsafe { &*var.threads.load(Ordering::Acquire) };
        let syncs = unsafe { &mut *self.sync_counts.load(Ordering::Acquire) };
        let self_thread_id = self.thread_id.load(Ordering::Acquire);

        for (id, thread) in threads.iter().filter(|(a, b)| **a != self_thread_id) {
            let thread_run_count = thread.run_count.load(Ordering::Acquire);
            syncs.insert(*id, thread_run_count as isize);
        }

        // this inner loop is per thread and shall wait until the reader threads are
        // finished
        for (id, thread) in threads.iter().filter(|(a, b)| **a != self_thread_id) {
            'per_thread: loop {
                if let Some(sync_counts) = syncs.get(id) {
                    if (sync_counts & 0x1) != 1 {
                        break 'per_thread;
                    }

                    if sync_counts != &(thread.run_count.load(Ordering::Acquire) as isize) {
                        break 'per_thread;
                    }

                    if self.write_clock.load(Ordering::Acquire) <= thread.local_clock.load(Ordering::Acquire) {
                        break 'per_thread;
                    }
                }
            }
        }
    }

    fn swap_write_logs(&self) {
        let log = self.w_log.load(Ordering::Acquire);

        self.w_log
            .store(self.w_log_quiescence.load(Ordering::Acquire), Ordering::Release);

        self.w_log_quiescence.store(log, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {

    use rand_utils::random::{string, usize};

    use super::TVar;

    fn rand_string() -> String {
        string(255)
    }

    #[inline(always)]
    fn rand_usize() -> usize {
        usize(usize::MAX)
    }

    /// This function will be run before any of the tests
    #[ctor::ctor]
    fn init_logger() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Off)
            .try_init();
    }

    #[test]
    fn test_read_write() {
        let t_var = TVar::new(0usize);
    }
}

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
//! ## Examples
//! ---
//! ```no_run
//! // no example yet
//! ```
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
    ops::{Deref, DerefMut},
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
pub type Result<T> = core::result::Result<T, TransactionError>;

/// Simplified atomic mutex
pub type ClonableMutex<T> = Arc<Mutex<T>>;

/// auto impl for return type
impl<T> ReturnType for T where T: Send + Sync + Clone + Sized {}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction failed")]
    Failed,

    #[error("Transaction alread running")]
    InProgress,

    #[error("Inner error occured ({0})")]
    Inner(String),

    #[error("Operation aborted")]
    Abort,

    /// This is semantically incorrect, but a strategy
    #[error("Operation retry")]
    Retry,
}

pub struct ReadGuard<'a, T>
where
    T: Clone,
{
    inner: Result<&'a T>,
    thread: &'a RluContext<T>,
}
impl<'a, T> ReadGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: Result<&'a T>, thread: &'a RluContext<T>) -> Self {
        Self { inner, thread }
    }
}

impl<'a, T> Drop for ReadGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        self.thread.read_unlock();
    }
}

impl<'a, T> Deref for ReadGuard<'a, T>
where
    T: Clone,
{
    type Target = Result<&'a T>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub enum WriteGuardInner<'a, T>
where
    T: Clone,
{
    /// a mutable reference
    Ref(&'a mut T),

    /// a copy, that needs to be written back into the log
    Copy(InnerVar<T>),
}

pub struct WriteGuard<'a, T>
where
    T: Clone,
{
    inner: WriteGuardInner<'a, T>,
    thread: &'a mut RluContext<T>,
}

impl<'a, T> Deref for WriteGuard<'a, T>
where
    T: Clone,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        match &self.inner {
            WriteGuardInner::Copy(copy) => match copy {
                InnerVar::Copy { data, .. } | InnerVar::Original { data, .. } => data,
            },
            WriteGuardInner::Ref(reference) => reference,
        }
    }
}

impl<'a, T> DerefMut for WriteGuard<'a, T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.inner {
            WriteGuardInner::Copy(copy) => match copy {
                InnerVar::Copy { ref mut data, .. } | InnerVar::Original { ref mut data, .. } => data,
            },
            WriteGuardInner::Ref(reference) => *reference,
        }
    }
}

impl<'a, T> WriteGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: WriteGuardInner<'a, T>, thread: &'a mut RluContext<T>) -> Self {
        Self { inner, thread }
    }
}

impl<'a, T> Drop for WriteGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let WriteGuardInner::Copy(inner) = &self.inner {
            self.thread.log.push(inner.clone())
        }

        self.thread.write_unlock();
    }
}

#[derive(Debug)]
pub struct RLUVar<T>
where
    T: Clone,
{
    inner: Arc<AtomicPtr<InnerVar<T>>>,
}

impl<T> RLUVar<T>
where
    T: Clone,
{
    /// This function consumes the [`RLUVar<T>`] and returns the inner value. Any copy
    /// allocated with the inner types will be deallocated as well
    pub fn take(&self) -> &T {
        match unsafe { &*self.inner.swap(std::ptr::null_mut(), Ordering::SeqCst) } {
            InnerVar::Copy { data, .. } | InnerVar::Original { data, .. } => data,
        }
    }
}

impl<T> Deref for RLUVar<T>
where
    T: Clone,
{
    type Target = InnerVar<T>;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.load(Ordering::Acquire) }
    }
}

impl<T> DerefMut for RLUVar<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.load(Ordering::Acquire) }
    }
}

impl<T> From<T> for RLUVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        RLUVar {
            inner: Arc::new(AtomicPtr::new(&mut value.into())),
        }
    }
}

impl<T> Clone for RLUVar<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub enum InnerVar<T>
where
    T: Clone,
{
    Original {
        locked_thread_id: Option<AtomicUsize>,
        copy: Option<*mut InnerVar<T>>,
        data: T,

        ctrl: Option<RLU<T>>,
    },

    Copy {
        locked_thread_id: Option<AtomicUsize>,
        original: *mut Self,
        data: T,

        ctrl: Option<RLU<T>>,
    },
}

impl<T> From<T> for InnerVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        Self::Original {
            data: value,
            locked_thread_id: None,
            copy: None,
            ctrl: None,
        }
    }
}

impl<T> Clone for InnerVar<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Copy {
                ctrl,
                data,
                locked_thread_id,
                original,
            } => Self::Copy {
                ctrl: ctrl.clone(),
                data: data.clone(),
                locked_thread_id: Some(AtomicUsize::new(match locked_thread_id {
                    Some(inner) => inner.load(Ordering::Acquire),
                    None => 0,
                })),
                original: *original,
            },
            Self::Original {
                copy,
                ctrl,
                data,
                locked_thread_id,
            } => Self::Original {
                copy: *copy,
                ctrl: ctrl.clone(),
                data: data.clone(),
                locked_thread_id: Some(AtomicUsize::new(match locked_thread_id {
                    Some(inner) => inner.load(Ordering::Acquire),
                    None => 0,
                })),
            },
        }
    }
}

/// that's the global object
pub struct RLU<T>
where
    T: Clone,
{
    global_count: Arc<AtomicUsize>,
    next_thread_id: Arc<AtomicUsize>,

    contexts: Arc<AtomicPtr<HashMap<usize, RluContext<T>>>>,
}

impl<T> Default for RLU<T>
where
    T: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RLU<T>
where
    T: Clone,
{
    pub fn new() -> Self {
        Self {
            global_count: Arc::new(AtomicUsize::new(0)),
            next_thread_id: Arc::new(AtomicUsize::new(0)),
            contexts: Arc::new(AtomicPtr::new(&mut HashMap::new())),
        }
    }

    pub fn create(&self, data: T) -> RLUVar<T> {
        RLUVar {
            inner: Arc::new(AtomicPtr::new(&mut InnerVar::Original {
                data,
                ctrl: Some(self.clone()),
                locked_thread_id: None,
                copy: None,
            })),
        }
    }

    /// executes a series of reads and writes
    pub fn execute<F>(&self, func: F) -> Result<()>
    where
        F: Fn(RluContext<T>) -> Result<()>,
    {
        loop {
            match func(self.context()) {
                Err(err) => {
                    match err {
                        TransactionError::Retry => {
                            // retry
                        }
                        _ => return Err(err),
                    }
                }
                Ok(_) => return Ok(()),
            }
        }
    }

    fn context(&self) -> RluContext<T> {
        self.next_thread_id.fetch_add(1, Ordering::SeqCst);

        RluContext {
            id: AtomicUsize::new(self.next_thread_id.load(Ordering::Acquire)),
            // TODO: provide `current_log`?
            log: Vec::new(),
            log_quiescence: Vec::new(),
            local_clock: AtomicUsize::new(0),
            write_clock: AtomicUsize::new(0),
            run_count: AtomicUsize::new(0),
            sync_count: AtomicPtr::new(&mut HashMap::new()),
            is_writer: AtomicBool::new(false),
            ctrl: Arc::new(self.clone()),
        }
    }
}

impl<T> Clone for RLU<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            global_count: self.global_count.clone(),
            next_thread_id: self.next_thread_id.clone(),
            contexts: self.contexts.clone(),
        }
    }
}

pub struct RluContext<T>
where
    T: Clone,
{
    id: AtomicUsize,
    log: Vec<InnerVar<T>>,
    log_quiescence: Vec<InnerVar<T>>,
    local_clock: AtomicUsize,
    write_clock: AtomicUsize,
    is_writer: AtomicBool,
    run_count: AtomicUsize,
    sync_count: AtomicPtr<HashMap<usize, usize>>,

    ctrl: Arc<RLU<T>>,
}

impl<T> RluContext<T>
where
    T: Clone,
{
    /// read
    /// TODO: RAII patter for reads
    pub fn get<'a>(&'a self, var: &'a RLUVar<T>) -> ReadGuard<T> {
        // prepare read lock
        self.read_lock();

        // if this is a copy, return the copy
        if let InnerVar::Copy { data, .. } = var.deref() {
            return ReadGuard::new(Ok(data), self);
        }

        // return the managing thread
        let (contexts, locked_thread_id) = match var.deref() {
            InnerVar::Original {
                ctrl, locked_thread_id, ..
            }
            | InnerVar::Copy {
                ctrl, locked_thread_id, ..
            } => (ctrl, locked_thread_id),
        };

        let (context, locked_thread_id) = match (contexts, locked_thread_id) {
            (Some(ctx), Some(id)) => {
                let contexts = unsafe { &*ctx.contexts.load(Ordering::Acquire) };
                (contexts.get(&id.load(Ordering::Acquire)), id)
            }
            (Some(ctx), None) => {
                println!("no locked thread");
                return ReadGuard::new(Err(TransactionError::Failed), self);
            }
            (None, Some(id)) => {
                println!("no context given");
                return ReadGuard::new(Err(TransactionError::Failed), self);
            }
            _ => {
                println!("neither context nor locking thread given");
                return ReadGuard::new(Err(TransactionError::Failed), self);
            }
        };

        // if this copy is locked by us, return the copy
        match var.deref() {
            InnerVar::Original { copy, .. }
                if locked_thread_id.load(Ordering::Acquire) == self.id.load(Ordering::Acquire) =>
            {
                let data = match copy {
                    Some(copy_data) => {
                        if let InnerVar::Copy {
                            locked_thread_id,
                            original,
                            data,
                            ctrl,
                        } = unsafe { &**copy_data }
                        {
                            return ReadGuard::new(Ok(data), self);
                        }
                    }
                    None => {}
                };
            }
            _ => {}
        }

        // check for stealing
        if self.local_clock.load(Ordering::SeqCst) >= context.unwrap().write_clock.load(Ordering::SeqCst) {
            if let Some(last) = context.unwrap().log.last() {
                match last {
                    InnerVar::Copy { data, .. } | InnerVar::Original { data, .. } => {
                        return ReadGuard::new(Ok(data), self)
                    }
                }
            }

            // FIXME
            // unreachable!()
        }

        match var.deref() {
            InnerVar::Original { data, .. } | InnerVar::Copy { data, .. } => ReadGuard::new(Ok(data), self),
        }
    }

    /// write
    pub fn get_mut<'a>(&'a mut self, var: &'a RLUVar<T>) -> Result<WriteGuard<T>> {
        self.write_lock();
        let self_id = self.id.load(Ordering::Acquire);

        let inner = unsafe { &mut *var.inner.load(Ordering::Acquire) };

        let (original, ctrl) = match inner {
            InnerVar::Copy {
                locked_thread_id, data, ..
            } => match locked_thread_id {
                Some(id) if id.load(Ordering::Acquire) != self_id => {
                    // changed to unequal
                    return Ok(WriteGuard::new(WriteGuardInner::Ref(data), self));
                }
                Some(id) => {
                    self.abort();

                    info!("Abort. Locking thread is same");

                    // yield?
                    std::thread::yield_now();

                    return Err(TransactionError::Retry);
                }
                None => {
                    self.abort();

                    info!("No locking thread is present");

                    // yield?
                    std::thread::yield_now();

                    return Err(TransactionError::Retry);
                }
            },
            InnerVar::Original { data, ctrl, .. } => (data, ctrl),
        };

        // TODO:
        // we want to have a mutable reference either to the copy, or
        // or to the mutable thread which keeps the copy to a log
        // - fixed for now.
        // - self fn will return a write guard with the same lifetime, on drop, the writeguard will write the remaining
        //   copy back, for later synchronization

        Ok(WriteGuard::new(
            WriteGuardInner::Copy(InnerVar::Copy {
                data: original.clone(),
                ctrl: ctrl.clone(),
                locked_thread_id: Some(AtomicUsize::new(self_id)),
                original: var.inner.load(Ordering::Acquire),
            }),
            self,
        ))
    }

    fn read_lock(&self) {
        self.local_clock.fetch_add(1, Ordering::SeqCst);
        self.is_writer.store(false, Ordering::SeqCst);
        self.run_count.fetch_add(1, Ordering::SeqCst);
    }

    fn read_unlock(&self) {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        if self.is_writer.load(Ordering::SeqCst) {
            self.commit_log()
        }
    }

    fn write_lock(&self) {
        self.is_writer.store(true, Ordering::Release);
    }

    fn write_unlock(&self) {
        self.is_writer.store(false, Ordering::Release);
        // TODO more
    }

    fn synchronize(&self) {
        let contexts = unsafe { &*self.ctrl.contexts.load(Ordering::Acquire) };
        let sync_count = unsafe { &mut *self.sync_count.load(Ordering::Acquire) };
        // sychronize with other contexts, collect their run stats
        for (id, ctx) in contexts {
            let id = ctx.id.load(Ordering::Acquire);
            if id == self.id.load(Ordering::Acquire) {
                continue;
            }
            let run_count = ctx.run_count.load(Ordering::Acquire);

            sync_count.insert(id, run_count);
        }

        // wait for other contexts
        for (id, ctx) in contexts {
            loop {
                if sync_count[id] & 0x1 == 0 {
                    // is inactive
                    break;
                }
                if sync_count[id] != ctx.run_count.load(Ordering::Acquire) {
                    // has progressed
                    break;
                }

                if self.write_clock.load(Ordering::Acquire) <= ctx.local_clock.load(Ordering::Acquire) {
                    // started after this context
                    break;
                }
            }
        }
    }

    fn commit_log(&self) {
        self.write_clock
            .store(self.ctrl.global_count.load(Ordering::Acquire) + 1, Ordering::Release);
        self.ctrl.global_count.fetch_add(1, Ordering::SeqCst);
        self.synchronize();

        self.write_clock.store(usize::MAX, Ordering::Release);
        self.swap_logs();
    }

    fn abort(&self) {
        self.run_count.fetch_add(1, Ordering::SeqCst);
    }

    fn swap_logs(&self) {
        todo!()
    }
}

// old -----------------------
mod old {

    use super::*;
    /// This is the global object for reading and writing
    pub struct TVar<T>
    where
        T: ReturnType + 'static,
    {
        /// the actual data
        data: Arc<AtomicPtr<T>>,

        /// a ptr to the write log copy inside an RLU thread
        copy_ptr: Arc<AtomicPtr<TVar<T>>>,

        /// indicating, if this is a copy
        is_copy: Arc<AtomicBool>,

        /// the current thread locking this object
        rlu_thread_id: Arc<AtomicIsize>,

        /// if this is a copy, this is the reference to the 'original'
        obj_reference: Arc<AtomicPtr<TVar<T>>>,

        /// all global related rlu objects reside here, since they are interested in synchronizing
        /// one object at a time
        global_clock: Arc<AtomicUsize>,

        /// a list of all threads monitoring this variable
        threads: Arc<AtomicPtr<HashMap<isize, &'static RLUContext<T>>>>,
    }

    impl<T> Clone for TVar<T>
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

                obj_reference: Arc::new(AtomicPtr::new(&self as *const _ as *mut TVar<T>)),

                global_clock: Arc::new(AtomicUsize::new(self.global_clock.load(Ordering::Acquire))),

                // the pointer to active threads can be safely cloned
                threads: self.threads.clone(),
            }
        }
    }

    impl<T> TVar<T>
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

        fn get_rlu_context<'a>(&self, id: &isize) -> &'a RLUContext<T> {
            let threads = unsafe { &*self.threads.load(Ordering::Acquire) };
            threads.get(id).unwrap()
        }
    }

    /// The [`RLUContext`] is a concurrent read / write instance bound to a `TVar`.
    /// It maintains two logs for writers, a local clock and a write clock. The local
    /// clock is being used to determine to read from the original object, or from another
    /// context's writer log.
    pub struct RLUContext<T>
    where
        T: ReturnType + 'static,
    {
        // the thread id
        thread_id: Arc<AtomicIsize>,

        /// first write log
        w_log: Arc<AtomicPtr<TVar<T>>>,

        /// second write log
        w_log_quiescence: Arc<AtomicPtr<TVar<T>>>,

        /// the run_count indicates the state of the thread.
        /// an even number signals a running thread, while an
        /// odd number a thread at rest
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

    impl<T> RLUContext<T>
    where
        T: ReturnType,
    {
        // pub fn with_func<F>(f: F) -> Result<()>
        // where
        //     F: Fn(Self) -> Result<()>,
        // {
        //     if GUARD.with(|inner| match inner.get() {
        //         true => true,
        //         false => {
        //             inner.set(true);
        //             false
        //         }
        //     }) {
        //         return Err(TransactionError::InProgress);
        //     }

        //     let tx = RLUContext {
        //         thread_id: Arc::new(AtomicIsize::new(-1)),
        //         w_log: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
        //         w_log_quiescence: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
        //         run_count: Arc::new(AtomicUsize::new(0)),
        //         local_clock: Arc::new(AtomicUsize::new(0)),
        //         write_clock: Arc::new(AtomicUsize::new(0)),
        //         is_writer: Arc::new(AtomicBool::new(false)),
        //         sync_counts: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
        //     };

        //     f(tx)
        // }

        pub fn new() -> Self {
            Self {
                thread_id: Arc::new(AtomicIsize::new(-1)),
                w_log: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
                w_log_quiescence: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
                run_count: Arc::new(AtomicUsize::new(0)),
                local_clock: Arc::new(AtomicUsize::new(0)),
                write_clock: Arc::new(AtomicUsize::new(0)),
                is_writer: Arc::new(AtomicBool::new(false)),
                sync_counts: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            }
        }

        // /// reads a snapshot of `T` and returns it
        // pub fn read<'a>(&self, var: &'a T) -> &'a T {
        //     // self.reader_lock(var);
        //     // let _inner = unsafe { &*self.deref(var).data.load(Ordering::Acquire).clone() };
        //     // self.reader_unlock(var);

        //     // _inner
        //     todo!()
        // }

        // pub fn write<'a>(&self, value: T, var: &'a TVar<T>) {
        //     self.try_lock(var);
        // }

        /// --- inner API

        fn reader_lock(&self, var: &TVar<T>) {
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

        fn reader_unlock(&self, var: &TVar<T>) {
            // increment number of runners
            self.run_count
                .store(self.run_count.load(Ordering::Acquire) + 1, Ordering::Release);

            if self.is_writer.load(Ordering::Acquire) {
                self.commit_write_log(var)
            }
        }

        /// function marker to abort at specific point
        /// may be replace with a function return
        fn abort(&self) {
            self.run_count.fetch_add(1, Ordering::SeqCst);
            if self.is_writer.load(Ordering::Acquire) {}
        }

        /// This is `read`
        fn deref<'a>(&self, var: &'a TVar<T>) -> &'a TVar<T> {
            // if this is a copy, return it
            if var.is_copy.load(Ordering::Acquire) {
                return unsafe { &*var.copy_ptr.load(Ordering::Acquire) };
            }

            // get the copy ptr
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

            let thread: &RLUContext<T> = var.get_rlu_context(&(thread_id));

            if self.local_clock.load(Ordering::Acquire) >= thread.write_clock.load(Ordering::Acquire) {
                return copy_ptr;
            }

            var
        }

        /// This is `write`
        fn try_lock(&self, var: &TVar<T>) -> Option<*const TVar<T>> {
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
                self.abort();

                // indicate retry
                return None;
            }

            let mut copy = var.clone();

            copy.obj_reference
                .store(var as *const _ as *mut TVar<T>, Ordering::Release);

            let self_thread_id = self.thread_id.load(Ordering::Acquire);
            var.rlu_thread_id.store(self_thread_id as isize, Ordering::Release);

            //
            self.w_log.store(&mut copy, Ordering::Release);

            if var
                .copy_ptr
                .compare_exchange(std::ptr::null_mut(), &mut copy, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                self.abort()
            }

            Some(&copy as *const _)
        }

        fn commit_write_log(&self, var: &TVar<T>) {
            self.write_clock
                .store(var.global_clock.load(Ordering::Acquire) + 1, Ordering::Release);

            var.global_clock.fetch_add(1, Ordering::SeqCst);

            self.synchronize(var);

            // - write back write log
            self.write_back_log(var);

            // - unlock write lock
            self.write_clock.store(usize::MAX, Ordering::Release);

            // - swap write logs
            self.swap_write_logs();
        }

        /// block this thread, until all other reading threads have finished
        fn synchronize(&self, var: &TVar<T>) {
            let threads = unsafe { var.threads.load(Ordering::Acquire).as_ref().unwrap() };
            let syncs = unsafe { &mut *self.sync_counts.load(Ordering::Acquire) };
            let self_thread_id = self.thread_id.load(Ordering::Acquire);

            for (id, thread) in threads.iter().filter(|(a, b)| **a != self_thread_id) {
                let thread_run_count = thread.run_count.load(Ordering::Acquire);
                syncs.insert(*id, thread_run_count as isize);
            }

            // this inner loop is per thread and shall wait until the reader threads are
            // finished
            for (id, thread) in threads.iter().filter(|(a, b)| **a != self_thread_id) {
                loop {
                    if let Some(sync_counts) = syncs.get(id) {
                        if (sync_counts & 0x1) != 1 {
                            break;
                        }

                        if sync_counts != &(thread.run_count.load(Ordering::Acquire) as isize) {
                            break;
                        }

                        if self.write_clock.load(Ordering::Acquire) <= thread.local_clock.load(Ordering::Acquire) {
                            break;
                        }
                    }
                }
            }
        }

        /// writes the logs back into memory
        fn write_back_log(&self, var: &TVar<T>) {}

        fn swap_write_logs(&self) {
            let log = self.w_log.load(Ordering::Acquire);

            self.w_log
                .store(self.w_log_quiescence.load(Ordering::Acquire), Ordering::Release);

            self.w_log_quiescence.store(log, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {

    use std::ops::DerefMut;

    use rand_utils::random::{string, usize};
    use threadpool::ThreadPool;

    use crate::rlu::{RLUVar, TransactionError, RLU};

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
            .filter_level(log::LevelFilter::Info)
            .try_init();
    }

    #[test]
    fn test_read_write() {
        const NUM_THREADS: usize = 2;
        const EXPECTED: usize = 9usize;

        let ctrl = RLU::new();
        let rlu_var: RLUVar<usize> = ctrl.create(5usize);

        let pool = ThreadPool::new(NUM_THREADS);
        {
            let r1 = rlu_var.clone();
            let c1 = ctrl.clone();

            pool.execute(move || {
                match c1.execute(|mut context| {
                    let mut data = context.get_mut(&r1)?;
                    let inner = data.deref_mut();

                    *inner += 9usize;

                    Ok(())
                }) {
                    Err(err) => {
                        println!("error {}", err);
                        Err(err)
                    }
                    Ok(()) => Ok(()),
                }
                .expect("Failed");
            });
        }

        for id in 0..(NUM_THREADS - 1) {
            let r1 = rlu_var.clone();
            let c1 = ctrl.clone();

            pool.execute(move || {
                if let Err(e) = c1.execute(|context| {
                    let data = context.get(&r1);
                    match *data {
                        Ok(inner) if *inner == EXPECTED => Ok(()),
                        Ok(inner) => Err(TransactionError::Inner(format!(
                            "Value is not expected: actual {}, expected {}",
                            *inner, EXPECTED
                        ))),
                        Err(ref e) => {
                            println!("error : {}", e);
                            Err(TransactionError::Abort)
                        }
                    }
                }) {
                    println!("Error occured: {}", e);
                }
            });
        }

        pool.join();

        let value = rlu_var.take();
        assert!(pool.panic_count().eq(&0));
        assert_eq!(value, &9)
    }
}

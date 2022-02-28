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
//! ## Features
//! ---
//! [x] - multiple readers / writers
//! [x] - lock free
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
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

// FIXME: this belongs to the former implementation
thread_local! {
    #[deprecated]
    static GUARD : Cell<bool> = Cell::new(false);
}

/// Virtual Type to use as return
pub trait ReturnType: Clone + Send + Sync + Sized {}

/// Global return type
pub type Result<T> = core::result::Result<T, TransactionError>;

/// Simplified atomic mutex
#[deprecated]
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

/// Conversion trait for all types to be heap allocated
/// and returned as raw mutable pointer
pub trait IntoRaw: Sized {
    /// Takes `self`, allocates heap space and retuns it as a raw mutable pointer
    fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }
}

impl<T> IntoRaw for T {}

struct RLULog<T>
where
    T: Clone,
{
    clear: AtomicUsize,
    current_log_index: AtomicUsize,
    logs: [Vec<T>; 2],
}

impl<T> Default for RLULog<T>
where
    T: Clone,
{
    fn default() -> Self {
        Self {
            clear: AtomicUsize::new(usize::MAX),
            current_log_index: AtomicUsize::new(0),
            logs: [Vec::new(), Vec::new()],
        }
    }
}

impl<T> RLULog<T>
where
    T: Clone,
{
    /// Selects the next internal log by incrementing the internal index mod the  number of logs
    pub fn next(&self) {
        let next = (self.current() + 1) % self.logs.len();
        self.clear.store(self.current(), Ordering::Release);
        self.current_log_index.store(next, Ordering::Release);
    }

    /// Returns the current index  of the log
    pub fn current(&self) -> usize {
        self.current_log_index.load(Ordering::Acquire)
    }
}

impl<T> Deref for RLULog<T>
where
    T: Clone,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.logs[self.current()]
    }
}

impl<T> DerefMut for RLULog<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        if let a @ 0..=1 = self.clear.swap(usize::MAX, Ordering::Acquire) {
            self.logs[0].clear()
        }

        &mut self.logs[self.current()]
    }
}

/// # Atomic &lt;T&gt;
///
/// Wrapper type for [`AtomicPtr`], but with extra heap allocation for the inner type.
///
/// ## Example
/// ```
/// use stronghold_rlu::rlu::Atomic;
/// let expected = 1024usize;
/// let atomic_usize = Atomic::from(expected);
/// assert_eq!(expected, *atomic_usize);
/// ```
pub struct Atomic<T>
where
    T: Clone,
{
    inner: AtomicPtr<T>,
}

impl<T> Atomic<T>
where
    T: Clone,
{
    /// Swaps the inner value and returns the old value.
    ///
    /// ## Safety
    /// This function is unsafe as it tries to dereference a raw pointer which must be allocated
    /// in accordance to the memory layout of a Box type.
    pub unsafe fn swap(&self, value: &mut T) -> T {
        let old = Box::from_raw(self.inner.swap(value, Ordering::Release));
        *old
    }
}

impl<T> Deref for Atomic<T>
where
    T: Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.load(Ordering::Acquire) }
    }
}

impl<T> DerefMut for Atomic<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.load(Ordering::Acquire) }
    }
}

impl<T> From<T> for Atomic<T>
where
    T: Clone + IntoRaw,
{
    fn from(value: T) -> Self {
        Self {
            inner: AtomicPtr::new(value.into_raw()),
        }
    }
}

impl<T> Clone for Atomic<T>
where
    T: Clone,
{
    /// This creates and returns a copy of the pointer to the inner value, not a copy of the value itself
    fn clone(&self) -> Self {
        Self {
            inner: AtomicPtr::new(self.inner.load(Ordering::Acquire)),
        }
    }
}

pub struct ReadGuard<'a, T>
where
    T: Clone,
{
    inner: Result<&'a Atomic<T>>,
    thread: &'a RluContext<T>,
}

impl<'a, T> ReadGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: Result<&'a Atomic<T>>, thread: &'a RluContext<T>) -> Self {
        Self { inner, thread }
    }
}

impl<'a, T> Drop for ReadGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let Ok(inner) = self.inner {
            self.thread.read_unlock(inner)
        }
    }
}

impl<'a, T> Deref for ReadGuard<'a, T>
where
    T: Clone,
{
    type Target = Result<&'a Atomic<T>>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// This inner enum of [`WriteGuard`]
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
    context: &'a mut RluContext<T>,
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
    pub fn new(inner: WriteGuardInner<'a, T>, context: &'a mut RluContext<T>) -> Self {
        Self { inner, context }
    }
}

impl<'a, T> Drop for WriteGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let WriteGuardInner::Copy(inner) = &self.inner {
            self.context.log.push(inner.clone())
        }

        self.context.write_unlock();
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
    T: Clone + std::fmt::Debug,
{
    /// This function returns the inner value.
    pub fn get(&self) -> &T {
        match unsafe { &*self.inner.load(Ordering::Acquire) } {
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
        unsafe { &*self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> DerefMut for RLUVar<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.load(Ordering::SeqCst) }
    }
}

impl<T> From<T> for RLUVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        RLUVar {
            inner: Arc::new(AtomicPtr::new(InnerVar::from(value).into_raw())),
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
        copy: Option<AtomicPtr<Self>>,
        data: Atomic<T>,
        ctrl: Option<RLU<T>>,
    },

    Copy {
        locked_thread_id: Option<AtomicUsize>,
        original: AtomicPtr<Self>,
        data: Atomic<T>,
        ctrl: Option<RLU<T>>,
    },
}

impl<T> From<T> for InnerVar<T>
where
    T: Clone,
{
    fn from(value: T) -> Self {
        Self::Original {
            data: value.into(),
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
                original: AtomicPtr::new(unsafe { &mut *original.load(Ordering::Acquire) }),
            },
            Self::Original {
                copy,
                ctrl,
                data,
                locked_thread_id,
            } => Self::Original {
                copy: copy
                    .as_ref()
                    .map(|inner| AtomicPtr::new(unsafe { &mut *inner.load(Ordering::Acquire) })),
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

/// [`RLU`] is the global context, where memory gets synchronized in concurrent setups. Since [`RLU`]
/// can have multiple instances, it can be used for multiple types at once.
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
    T: Clone + IntoRaw,
{
    pub fn new() -> Self {
        // store the context resolver on the heap
        let contexts_ptr = Box::into_raw(Box::new(HashMap::new()));

        Self {
            global_count: Arc::new(AtomicUsize::new(0)),
            next_thread_id: Arc::new(AtomicUsize::new(0)),
            contexts: Arc::new(AtomicPtr::new(contexts_ptr)),
        }
    }

    pub fn create(&self, data: T) -> RLUVar<T> {
        // the moved data variable will live on the heap

        RLUVar {
            inner: Arc::new(AtomicPtr::new(
                InnerVar::Original {
                    data: data.into(),
                    ctrl: Some(self.clone()),
                    locked_thread_id: None,
                    copy: None,
                }
                .into_raw(),
            )),
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
            log: RLULog::default(),
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

/// The [`RluContext`] stores per thread specific information of [`InnerVar`] and is
/// being used to get im/mutable references to memory.
pub struct RluContext<T>
where
    T: Clone,
{
    id: AtomicUsize,
    log: RLULog<InnerVar<T>>,
    local_clock: AtomicUsize,
    write_clock: AtomicUsize,
    is_writer: AtomicBool,
    run_count: AtomicUsize,
    sync_count: AtomicPtr<HashMap<usize, usize>>,

    ctrl: Arc<RLU<T>>,
}

/// [`Read<T>`] provides immutable read access to the synchronized data
/// via the current managing context.
pub trait Read<T>
where
    T: Clone,
{
    /// Returns an immutable [`ReadGuard`] on the value of [`RLUVar`]
    ///
    /// This function effectively returns either the original value, if it
    /// has not been modified, or an immutable reference to the underlying
    /// write log, if the log has not been commited to memory yet. The [`ReadGuard`]
    /// ensures that after dereferencing and reading the value, all outstanding
    /// commits to the internal value will be conducted.
    ///
    /// # Example
    /// ```
    /// use stronghold_rlu::rlu::*;
    ///
    /// // create simple value, that should be managed by RLU
    /// let value = 6usize;
    ///
    /// // first we need to create a controller
    /// let ctrl = RLU::new();
    ///
    /// // via the controller  we create a RLUVar reference
    /// let rlu_var: RLUVar<usize> = ctrl.create(value);
    ///
    /// // we clone the reference to it to use it inside a thread
    /// let var_1 = rlu_var.clone();
    ///
    /// // via the controller we can spawn a thread safe context
    /// ctrl.execute(move |context| {
    ///     let inner = context.get(&var_1);
    ///     match *inner {
    ///         Ok(inner) => {
    ///             assert_eq!(**inner, 6);
    ///         }
    ///         _ => return Err(TransactionError::Failed),
    ///     }
    ///     Ok(())
    /// });
    /// ```
    fn get<'a>(&'a self, var: &'a RLUVar<T>) -> ReadGuard<T>;
}

/// [`Write<T>`] gives mutable access to synchronized value via the current managing
/// context.
pub trait Write<T>
where
    T: Clone,
{
    /// Returns an mutable [`WriteGuard`] on the value of [`RLUVar`]
    ///
    /// This function returns a mutable copy if the original value. The [`WriteGuard`]
    /// ensures that after dereferencing and writing to the value, the internal log
    /// will be updated to the most recent change
    ///
    /// # Example
    /// ```
    /// use stronghold_rlu::rlu::*;
    ///
    /// // create simple value, that should be managed by RLU
    /// let value = 6usize;
    ///
    /// // first we need to create a controller
    /// let ctrl = RLU::new();
    ///
    /// // via the controller  we create a RLUVar reference
    /// let rlu_var: RLUVar<usize> = ctrl.create(value);
    ///
    /// // we clone the reference to it to use it inside a thread
    /// let var_1 = rlu_var.clone();
    ///
    /// // via the controller we can spawn a thread safe context
    /// ctrl.execute(move |mut context| {
    ///     let mut inner = context.get_mut(&var_1)?;
    ///     let data = &mut *inner;
    ///     *data += 10;
    ///     Ok(())
    /// });
    ///
    /// assert_eq!(*rlu_var.get(), 16);
    /// ```
    fn get_mut<'a>(&'a mut self, var: &'a RLUVar<T>) -> Result<WriteGuard<T>>;
}

impl<T> Read<T> for RluContext<T>
where
    T: Clone,
{
    fn get<'a>(&'a self, var: &'a RLUVar<T>) -> ReadGuard<T> {
        // prepare read lock
        self.read_lock();

        // FIXME:
        // this match is irritating.
        // the rlu paper states, that if the original has a reference to a copy
        // the copy shall be returned, otherwise the copy is zero
        // and the original is the most valid state and shall be returned
        match var.deref() {
            InnerVar::Copy { data, .. } => {
                return ReadGuard::new(Ok(data), self);
            }
            InnerVar::Original { data, copy, .. } => {
                if copy.is_none() {
                    return ReadGuard::new(Ok(data), self);
                }
            }
        }

        // return the managing thread
        let (contexts, locked_thread_id) = match var.deref() {
            InnerVar::Original { data, .. } => {
                return ReadGuard::new(Ok(data), self);
            }
            InnerVar::Copy {
                ctrl,
                locked_thread_id,
                data,
                ..
            } => (ctrl, locked_thread_id),
        };

        let (context, locked_thread_id) = match (contexts, locked_thread_id) {
            (Some(ctx), Some(id)) => {
                let contexts = unsafe { &*ctx.contexts.load(Ordering::Acquire) };
                (contexts.get(&id.load(Ordering::Acquire)), id)
            }
            (Some(ctx), None) => {
                return ReadGuard::new(Err(TransactionError::Failed), self);
            }
            _ => {
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
                        } = unsafe { &*copy_data.load(Ordering::Acquire) }
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
        }

        match var.deref() {
            InnerVar::Original { data, .. } | InnerVar::Copy { data, .. } => ReadGuard::new(Ok(data), self),
        }
    }
}

impl<T> Write<T> for RluContext<T>
where
    T: Clone,
{
    fn get_mut<'a>(&'a mut self, var: &'a RLUVar<T>) -> Result<WriteGuard<T>> {
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
                    return Err(TransactionError::Retry);
                }
                None => {
                    self.abort();
                    return Err(TransactionError::Retry);
                }
            },
            InnerVar::Original { data, ctrl, .. } => (data, ctrl),
        };

        Ok(WriteGuard::new(
            WriteGuardInner::Copy(InnerVar::Copy {
                data: original.clone(),
                ctrl: ctrl.clone(),
                locked_thread_id: Some(AtomicUsize::new(self_id)),
                original: AtomicPtr::new(var.inner.load(Ordering::Acquire)),
            }),
            self,
        ))
    }
}

impl<T> RluContext<T>
where
    T: Clone,
{
    fn read_lock(&self) {
        self.local_clock.fetch_add(1, Ordering::SeqCst);
        self.is_writer.store(false, Ordering::SeqCst);
        self.run_count.fetch_add(1, Ordering::SeqCst);
    }

    fn read_unlock(&self, var: &Atomic<T>) {
        self.run_count.fetch_add(1, Ordering::SeqCst);

        if self.is_writer.load(Ordering::SeqCst) {
            self.commit_log(var)
        }
    }

    fn write_lock(&self) {
        self.is_writer.store(true, Ordering::Release);
    }

    fn write_unlock(&self) {
        self.is_writer.store(false, Ordering::Release);
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

    fn commit_log(&self, var: &Atomic<T>) {
        self.write_clock
            .store(self.ctrl.global_count.load(Ordering::Acquire) + 1, Ordering::Release);
        self.ctrl.global_count.fetch_add(1, Ordering::SeqCst);
        self.synchronize();

        unsafe {
            for inner in &*self.log {
                if let InnerVar::Copy { data, .. } = inner {
                    let update = (**data).clone();
                    var.swap(&mut Box::from(update));
                }
            }
        };

        self.write_clock.store(usize::MAX, Ordering::Release);
        self.swap_logs();
    }

    fn abort(&self) {
        self.run_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Swaps the logs internally
    fn swap_logs(&self) {
        self.log.next();
    }
}

#[cfg(test)]
mod tests {

    use super::Atomic;
    use crate::rlu::RLULog;
    use rand_utils::random::{string, usize};

    fn rand_string() -> String {
        string(255)
    }

    #[inline(always)]
    fn rand_usize() -> usize {
        usize(usize::MAX)
    }

    #[test]
    fn test_rlu_log() {
        let mut log = RLULog::<usize>::default();
        assert_eq!(log.current(), 0);

        log.push(1);
        log.push(1);

        log.next();
        log.push(1);
        log.push(1);
        assert_eq!(log.current(), 1);
        log.next();
        log.push(1);
        log.push(1);
        assert_eq!(log.current(), 0);
    }

    #[test]
    fn test_atomic_type() {
        let num_runs = 1000;

        for _ in 0..num_runs {
            let expected = rand_string();
            let mut expected_mod = expected.clone();
            expected_mod.push_str("_modified");

            let atomic_string = Atomic::from(expected.clone());
            assert_eq!(expected, *atomic_string);

            unsafe { atomic_string.swap(&mut expected_mod) };
            assert_eq!(expected_mod, *atomic_string);
        }
    }
}

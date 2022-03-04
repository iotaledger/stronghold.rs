// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code, unused_variables)]

use log::*;
use std::{
    collections::HashMap,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{Atomic, BusyBreaker, InnerVar, IntoRaw, RLULog, RLUVar, ReadGuard, WriteGuard, WriteGuardInner};

/// Global return type
pub type Result<T> = core::result::Result<T, TransactionError>;

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction failed")]
    Failed,

    #[error("Transaction already running")]
    InProgress,

    #[error("Inner error occured ({0})")]
    Inner(String),

    #[error("Operation aborted")]
    Abort,
}

pub struct RLUObject<T>
where
    T: Clone,
{
    rlu: Arc<RLU<T>>,
    var: Arc<RLUVar<T>>,
}

impl<T> From<T> for RLUObject<T>
where
    T: Clone,
{
    fn from(data: T) -> Self {
        let rlu = Arc::new(RLU::default());
        let var = Arc::new(rlu.create(data));

        Self { rlu, var }
    }
}

impl<T> RLUObject<T>
where
    T: Clone,
{
    pub fn ctrl(&self) -> Arc<RLU<T>> {
        self.rlu.clone()
    }

    pub fn var(&self) -> &Arc<RLUVar<T>> {
        &self.var
    }
}

impl<T> Clone for RLUObject<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rlu: self.rlu.clone(),
            var: self.var.clone(),
        }
    }
}

/// Additional configuration for [`RLU`]. The internal execution
/// can be either [`RLUConfig::Abort`], if operation failed, [`RLUConfig::Retry`] again
/// an unlimited number of times, or [`RLUConfig::RetryWithBreaker`] with a busy breaker.
#[derive(Clone)]
pub enum RLUStrategy {
    /// Abort exeuction on failure
    Abort,

    /// Retry endlessly executing the calling function until
    /// it succeeds. A possible used case for this might be to
    /// check for a record again and again, until the corresponding
    /// write has occured. The number of internal retries should be
    /// really small in order to avoid any deadlocks.
    Retry,

    /// Try with a exponential breaker. Using a breaker that trips after
    /// an configurable amount of time is a trade-off between correctness of
    /// writes and code that tries to access a value that may not exists yet,
    /// but will be written by a future call into RLU augmented data structures.
    /// One such situation might occur, when integrating RLU into eg. a Cache
    /// data structure, where data is written and read from concurrently.
    /// Another calling process might assume the existence of a value, but writes
    /// to it might not be finished but will eventually land. This case can be mitigated
    /// by a "normal" retry, as the write can eventually be retrieved to be read.
    ///
    /// If it is uncertain, that a write has occured a retry with the breaker might
    /// give enough time to wait for the write, while not creating an infinite
    /// busy wait on the calling thread.
    RetryWithBreaker(BusyBreaker),
}

/// [`RLU`] is the global context, where memory gets synchronized in concurrent setups. Since [`RLU`]
/// can have multiple instances, it can be used for multiple types at once.
pub struct RLU<T>
where
    T: Clone,
{
    global_count: Arc<AtomicUsize>,
    next_thread_id: Arc<AtomicUsize>,

    // a map (should be array) of threads / contexts
    contexts: Arc<AtomicPtr<HashMap<usize, RluContext<T>>>>,

    strategy: RLUStrategy,
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
    /// Creates a new [`RLU`] with a [`RLUStrategy::Retry`] strategy.
    pub fn new() -> Self {
        Self::with_strategy(RLUStrategy::Retry)
    }

    /// Creates a new [`RLU`] with a defined strategy for handling the results of executing
    /// transactional functions.
    pub fn with_strategy(strategy: RLUStrategy) -> Self {
        // store the context resolver on the heap
        let contexts_ptr = Box::into_raw(Box::new(HashMap::new()));

        Self {
            global_count: Arc::new(AtomicUsize::new(0)),
            next_thread_id: Arc::new(AtomicUsize::new(0)),
            contexts: Arc::new(AtomicPtr::new(contexts_ptr)),
            strategy,
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
        let breaker = BusyBreaker::default();

        loop {
            match func(self.context()) {
                Err(err) => {
                    match &self.strategy {
                        RLUStrategy::Retry => {}
                        RLUStrategy::RetryWithBreaker(breaker) => {
                            // Keep the cpu busy for minimal amount of time
                            // WARNING: This can failed, because the breaker has reached the internal limits
                            // Using the breaker is a heuristic to wait for a certain amount of time until
                            // another thread has commited work. This should be configurable
                            breaker.spin().map_err(|e| TransactionError::Inner(e.to_string()))?;
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
            id: AtomicUsize::new(self.next_thread_id.load(Ordering::SeqCst)),
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
            strategy: self.strategy.clone(),
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
                let contexts = unsafe { &*ctx.contexts.load(Ordering::SeqCst) };
                (contexts.get(&id.load(Ordering::SeqCst)), id)
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
                if locked_thread_id.load(Ordering::SeqCst) == self.id.load(Ordering::SeqCst) =>
            {
                let data = match copy {
                    Some(copy_data) => {
                        if let InnerVar::Copy {
                            locked_thread_id,
                            original,
                            data,
                            ctrl,
                        } = unsafe { &*copy_data.load(Ordering::SeqCst) }
                        {
                            return ReadGuard::new(Ok(data), self);
                        }
                    }
                    None => {}
                };
            }
            _ => {}
        }
        let context = match context {
            Some(c) => c,
            None => return ReadGuard::new(Err(TransactionError::Failed), self),
        };

        // check for stealing
        if self.local_clock.load(Ordering::SeqCst) >= context.write_clock.load(Ordering::SeqCst) {
            if let Some(last) = context.log.last() {
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

        let self_id = self.id.load(Ordering::SeqCst);

        let inner = unsafe { &mut *var.inner.load(Ordering::SeqCst) };

        let (original, ctrl) = match inner {
            InnerVar::Copy {
                locked_thread_id, data, ..
            } => match locked_thread_id {
                Some(id) if id.load(Ordering::SeqCst) != self_id => {
                    // changed to unequal
                    return Ok(WriteGuard::new(WriteGuardInner::Ref(data), self));
                }
                Some(id) => {
                    self.abort();
                    return Err(TransactionError::Failed);
                }
                None => {
                    self.abort();
                    return Err(TransactionError::Failed);
                }
            },
            InnerVar::Original { data, ctrl, .. } => (data, ctrl),
        };

        Ok(WriteGuard::new(
            WriteGuardInner::Copy(InnerVar::Copy {
                data: original.clone(),
                ctrl: ctrl.clone(),
                locked_thread_id: Some(AtomicUsize::new(self_id)),
                original: AtomicPtr::new(var.inner.load(Ordering::SeqCst)),
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

    pub(crate) fn read_unlock(&self, var: &Atomic<T>) {
        self.run_count.fetch_add(1, Ordering::SeqCst);

        if self.is_writer.load(Ordering::SeqCst) {
            self.commit_log(var)
        }
    }

    pub(crate) fn write_lock(&self) {
        self.is_writer.store(true, Ordering::SeqCst);
    }

    pub(crate) fn write_unlock(&self) {
        self.is_writer.store(false, Ordering::SeqCst);
    }

    pub(crate) fn inner_log(&mut self) -> &mut RLULog<InnerVar<T>> {
        &mut self.log
    }

    fn synchronize(&self) {
        let contexts = unsafe { &*self.ctrl.contexts.load(Ordering::SeqCst) };
        let sync_count = unsafe { &mut *self.sync_count.load(Ordering::SeqCst) };

        // sychronize with other contexts, collect their run stats
        for (id, ctx) in contexts {
            let id = ctx.id.load(Ordering::SeqCst);
            if id == self.id.load(Ordering::SeqCst) {
                continue;
            }
            let run_count = ctx.run_count.load(Ordering::SeqCst);

            sync_count.insert(id, run_count);
        }

        // wait for other contexts
        for (id, ctx) in contexts {
            loop {
                if sync_count[id] & 0x1 == 0 {
                    // is inactive
                    break;
                }
                if sync_count[id] != ctx.run_count.load(Ordering::SeqCst) {
                    // has progressed
                    break;
                }

                if self.write_clock.load(Ordering::SeqCst) <= ctx.local_clock.load(Ordering::SeqCst) {
                    // started after this context
                    break;
                }
            }
        }
    }

    fn commit_log(&self, var: &Atomic<T>) {
        self.write_clock
            .store(self.ctrl.global_count.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        self.ctrl.global_count.fetch_add(1, Ordering::SeqCst);
        self.synchronize();

        unsafe {
            for log_item in self.log.iter().flatten() {
                if let InnerVar::Copy { data, .. } = log_item {
                    let update = data;
                    var.swap(&mut Box::from(update.clone()));
                    // CLONE!
                }
            }
        };

        self.write_clock.store(usize::MAX, Ordering::SeqCst);
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

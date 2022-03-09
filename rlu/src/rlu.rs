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

use crate::{
    var::InnerVarCopy, Atomic, BusyBreaker, InnerVar, IntoRaw, RLULog, RLUVar, Read, ReadGuard, Write, WriteGuard,
    WriteGuardInner,
};

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
/// can be either [`crate::RLUConfig::Abort`], if operation failed, [`crate::RLUConfig::Retry`] again
/// an unlimited number of times, or [`crate::RLUConfig::RetryWithBreaker`] with a busy breaker.
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
                InnerVar {
                    data: Atomic::from(data),
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
                            // WARNING: This can fail, because the breaker has reached the internal limits
                            // Using the breaker is a heuristic to wait for a certain amount of time until
                            // another thread has commited work.
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
    log: RLULog<InnerVarCopy<T>>,
    local_clock: AtomicUsize,
    write_clock: AtomicUsize,
    is_writer: AtomicBool,
    run_count: AtomicUsize,
    sync_count: AtomicPtr<HashMap<usize, usize>>,

    ctrl: Arc<RLU<T>>,
}

impl<T> Read<T> for RluContext<T>
where
    T: Clone,
{
    fn get<'a>(&'a self, var: &'a RLUVar<T>) -> ReadGuard<T> {
        // prepare read lock
        self.read_lock();

        // get inner var
        let inner = var.deref();

        // if object is unlocked, it has no copy. return the original
        if var.is_unlocked() {
            return ReadGuard::new(Ok(&inner.data), self);
        }

        let copy = match &inner.copy {
            Some(copy_ptr) => {
                let ptr = copy_ptr.load(Ordering::SeqCst);
                if ptr.is_null() {
                    return ReadGuard::new(Err(TransactionError::Inner("Copy is null reference".to_string())), self);
                }
                unsafe { &mut *ptr }
            }
            None => return ReadGuard::new(Err(TransactionError::Inner("Copy is null reference".to_string())), self),
        };

        // get the modifying context of the var
        let (ctrl, id) = (&inner.ctrl, &inner.locked_thread_id);

        // check, if context and id are present
        let (ctx, id) = match (ctrl, id) {
            (Some(ctx), Some(id)) => {
                let contexts = unsafe { &*ctx.contexts.load(Ordering::SeqCst) };
                (contexts.get(&id.load(Ordering::SeqCst)), id)
            }
            _ => {
                return ReadGuard::new(Err(TransactionError::Failed), self);
            }
        };

        let copy_lock_id = match &copy.locked_thread_id {
            Some(atomic_id) => atomic_id.load(Ordering::SeqCst),
            None => return ReadGuard::new(Err(TransactionError::Inner("No locked thread".to_string())), self),
        };

        // unpack context ids
        let (var_id, self_id) = (copy_lock_id, self.id.load(Ordering::SeqCst));

        if var_id == self_id {
            return ReadGuard::new(Ok(&copy.data), self);
        }

        // // if this copy is locked by us, return the copy
        // match inner {
        //     InnerVar::Original {
        //         copy: Some(copy_data), ..
        //     } if var_id == self_id => {
        //         if let InnerVar::Copy {
        //             locked_thread_id,
        //             original,
        //             data,
        //             ctrl,
        //         } = unsafe { &*copy_data.load(Ordering::SeqCst) }
        //         {
        //             return ReadGuard::new(Ok(data), self);
        //         }
        //     }
        //     _ => {}
        // }

        // no context is an error
        if ctx.is_none() {
            return ReadGuard::new(Err(TransactionError::Failed), self);
        }

        // unwrap context
        let context = &ctx.unwrap();

        // check for stealing
        if self.local_clock.load(Ordering::SeqCst) >= context.write_clock.load(Ordering::SeqCst) {
            if let Some(last) = context.log.last() {
                return ReadGuard::new(Ok(&last.data), self);
            }
        }

        // no steal, return object
        ReadGuard::new(Ok(&inner.data), self)
    }
}

impl<T> Write<T> for RluContext<T>
where
    T: Clone,
{
    fn get_mut<'a>(&'a mut self, var: &'a RLUVar<T>) -> Result<WriteGuard<T>> {
        self.set_writer();

        // load mutable pointer
        let inner_ptr = var.inner.load(Ordering::SeqCst);

        // check pointer for null
        if inner_ptr.is_null() {
            return Err(TransactionError::Inner("Null reference".to_string()));
        }

        if var.is_unlocked() {
            // TODO: return obj
        }

        // deref pointer
        let inner = unsafe { &mut *inner_ptr };

        // get current id of self
        let self_id = self.id.load(Ordering::SeqCst);

        let copy = match &inner.copy {
            Some(copy_ptr) => {
                let ptr = copy_ptr.load(Ordering::SeqCst);
                if ptr.is_null() {
                    return Err(TransactionError::Inner("Copy is null reference".to_string()));
                }
                unsafe { &mut *ptr }
            }
            None => return Err(TransactionError::Inner("Copy is null reference".to_string())),
        };

        // get locked id
        let copy_lock_id = match &copy.locked_thread_id {
            Some(atomic_id) => atomic_id.load(Ordering::SeqCst),
            None => return Err(TransactionError::Inner("No locked thread".to_string())),
        };

        if self_id == copy_lock_id {
            // TODO: return copy here
        }

        let (original, ctrl) = (&inner.data, &inner.ctrl);

        // create copied var
        let inner_copy = InnerVarCopy {
            data: original.clone(),
            locked_thread_id: Some(AtomicUsize::new(self_id)),
            original: AtomicPtr::new(var.inner.load(Ordering::SeqCst)),
        }
        .into_raw();

        inner.copy.replace(AtomicPtr::new(inner_copy));

        Ok(WriteGuard::new(WriteGuardInner::Copy(inner_copy), self))
    }
}

impl<T> RluContext<T>
where
    T: Clone,
{
    pub fn read_lock(&self) {
        self.local_clock.fetch_add(1, Ordering::SeqCst);
        self.is_writer.store(false, Ordering::SeqCst);
        self.run_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn read_unlock(&self, var: &Atomic<T>) {
        self.run_count.fetch_add(1, Ordering::SeqCst);

        if self.is_writer.load(Ordering::SeqCst) {
            self.commit_log(var)
        }
    }

    pub(crate) fn set_writer(&self) {
        self.is_writer.store(true, Ordering::SeqCst);
    }

    pub fn dereference<'a>(&self, var: &'a RLUVar<T>) -> Option<&'a T> {
        // get inner var
        let inner = var.deref();

        // if object is unlocked, it has no copy. return the original
        if var.is_unlocked() {
            return Some(&inner.data);
        }

        // the paper describes to check, if var already references a copy
        // but we explicitly split (inner) var and it's copy.
        // if this is required, we would need to rebuild the underlying structure

        let copy = match &inner.copy {
            Some(copy_ptr) => {
                let ptr = copy_ptr.load(Ordering::SeqCst);
                assert!(!ptr.is_null());

                unsafe { &mut *ptr }
            }
            None => return None,
        };

        let self_id = self.id.load(Ordering::SeqCst);
        let copy_lock_id = match &copy.locked_thread_id {
            Some(id) => id.load(Ordering::SeqCst),
            None => 0,
        };

        if self_id == copy_lock_id {
            return Some(&copy.data);
        }

        // get other context, that locks the copy
        match &var.ctrl {
            Some(control) => {
                let ptr = control.contexts.load(Ordering::SeqCst);
                assert!(!ptr.is_null());

                let all_contexts = unsafe { &*ptr };
                let locking_context = match all_contexts.get(&copy_lock_id) {
                    Some(ctx) => ctx,
                    None => return None,
                };

                let write_clock = locking_context.write_clock.load(Ordering::SeqCst);
                let local_clock = self.local_clock.load(Ordering::SeqCst);

                if write_clock <= local_clock {
                    // copy is most recent
                    return Some(&copy.data);
                }
            }
            None => return None,
        }

        Some(&inner.data)
    }

    pub(crate) fn inner_log(&mut self) -> &mut RLULog<InnerVarCopy<T>> {
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

        // unsafe {
        for item in self.log.iter().flatten() {
            // let update = data.inner.load(Ordering::SeqCst);

            // WE have to swap it, but comment it out until we find a solution for mutablity
            // var.swap(&mut item.data);
        }
        // };

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

// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code, unused_variables)]

use log::*;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use crate::rlu::{var::InnerVarCopy, BusyBreaker, InnerVar, RLULog, RLUVar, Read, ReadGuard, Write, WriteGuard};

/// Global return type
pub type Result<T> = core::result::Result<T, TransactionError>;

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("transaction failed")]
    Failed,

    #[error("transaction already running")]
    InProgress,

    #[error("inner error occured ({0})")]
    Inner(String),

    #[error("operation aborted")]
    Abort,

    #[error("no copy present")]
    NoCopyPresent,

    #[error("would block")]
    Blocking,
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
/// can be either [`crate::rlu::RLUStrategy::Abort`], if operation failed, [`crate::rlu::RLUStrategy::Retry`] again
/// an unlimited number of times, or [`crate::rlu::RLUStrategy::RetryWithBreaker`] with a busy breaker.
#[derive(Clone)]
pub enum RLUStrategy {
    /// Abort execution on failure
    Abort,

    /// Retry executing the calling function repeatedly until
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
    contexts: Arc<Mutex<HashMap<usize, Arc<RluContext<T>>>>>,

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
    T: Clone,
{
    /// Creates a new [`RLU`] with a [`RLUStrategy::Retry`] strategy.
    pub fn new() -> Self {
        Self::with_strategy(RLUStrategy::Retry)
    }

    /// Creates a new [`RLU`] with a defined strategy for handling the results of executing
    /// transactional functions.
    pub fn with_strategy(strategy: RLUStrategy) -> Self {
        // store the context resolver on the heap

        Self {
            global_count: Arc::new(AtomicUsize::new(0)),
            next_thread_id: Arc::new(AtomicUsize::new(0)),
            contexts: Arc::new(Mutex::new(HashMap::new())),
            strategy,
        }
    }

    pub fn create(&self, data: T) -> RLUVar<T> {
        RLUVar {
            inner: Arc::new(InnerVar {
                data: Arc::new(Mutex::new(data)),
                ctrl: Some(self.clone()),
                locked_thread_id: None,
                copy: Arc::new(Mutex::new(None)),
            }),
        }
    }

    /// executes a series of reads and writes
    pub fn execute<F>(&self, func: F) -> Result<()>
    where
        F: Fn(Arc<RluContext<T>>) -> Result<()>,
    {
        let breaker = BusyBreaker::default();

        loop {
            match func(self.context()?) {
                Err(err) => {
                    match &self.strategy {
                        RLUStrategy::Retry => {
                            info!("retry -> error: {}", err);
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        RLUStrategy::RetryWithBreaker(breaker) => {
                            // Keep the cpu busy for minimal amount of time
                            // WARNING: This can fail, because the breaker has reached the internal limits
                            // Using the breaker is a heuristic to wait for a certain amount of time until
                            // another thread has commited work.
                            breaker.spin().map_err(|e| TransactionError::Inner(e.to_string()))?;
                        }
                        _ => {
                            info!("other -> error: {}", err);
                            return Err(err);
                        }
                    }
                }
                Ok(_) => return Ok(()),
            }
        }
    }

    fn context(&self) -> Result<Arc<RluContext<T>>> {
        let id = self.next_thread_id.fetch_add(1, Ordering::SeqCst);

        let context = Arc::new(RluContext {
            id: AtomicUsize::new(id),
            log: Arc::new(Mutex::new(RLULog::default())),
            local_clock: AtomicUsize::new(0),
            write_clock: AtomicUsize::new(0),
            run_count: AtomicUsize::new(0),
            sync_count: Arc::new(Mutex::new(HashMap::default())),
            is_writer: AtomicBool::new(false),
            ctrl: Arc::new(self.clone()),
        });
        info!("({}) create context id {}", id, id);

        info!("({}) Locking controller context", id);
        let mut lock = self.contexts.try_lock().map_err(|e| TransactionError::Blocking)?;
        lock.deref_mut().insert(id, context.clone());
        drop(lock);
        info!("({}) Unlocking controller context", id);

        Ok(context)
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
    pub(crate) id: AtomicUsize,
    pub(crate) log: Arc<Mutex<RLULog<Arc<InnerVarCopy<T>>>>>,
    local_clock: AtomicUsize,
    write_clock: AtomicUsize,
    is_writer: AtomicBool,
    run_count: AtomicUsize,
    sync_count: Arc<Mutex<HashMap<usize, usize>>>,

    ctrl: Arc<RLU<T>>,
}

impl<T> Read<T> for RluContext<T>
where
    T: Clone,
{
    fn get<'a>(&'a self, var: &'a RLUVar<T>) -> Result<ReadGuard<'a, T>> {
        self.read_lock();
        self.dereference(var)
    }
}

impl<T> Write<T> for RluContext<T>
where
    T: Clone,
{
    fn get_mut<'a>(&'a self, var: &'a RLUVar<T>) -> Result<WriteGuard<'a, T>> {
        self.read_lock();
        self.try_lock(var)
    }
}

impl<T> RluContext<T>
where
    T: Clone,
{
    pub fn read_lock(&self) {
        self.is_writer.store(false, Ordering::SeqCst);
        self.run_count.fetch_add(1, Ordering::SeqCst);
        self.local_clock
            .store(self.ctrl.global_count.load(Ordering::SeqCst), Ordering::SeqCst);
        info!("({}) READ LOCK", self.id.load(Ordering::SeqCst));
    }

    pub fn read_unlock(&self) -> Result<()> {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        if self.is_writer.load(Ordering::SeqCst) {
            self.commit_log()?;
        }

        info!("({}) READ UNLOCK", self.id.load(Ordering::SeqCst));
        Ok(())
    }

    pub(crate) fn set_writer(&self) {
        self.is_writer.store(true, Ordering::SeqCst);
    }

    #[inline]
    pub fn dereference<'a>(&'a self, var: &'a RLUVar<T>) -> Result<ReadGuard<'a, T>> {
        // get inner var
        let inner_data = var.try_inner()?;

        let self_id = self.id.load(Ordering::SeqCst);

        // if object is unlocked, it has no copy. return the original
        if var.is_unlocked() {
            info!("({}) return unlocked var", self_id);
            return Ok(ReadGuard::from_baseguard(inner_data, self));
        }

        info!("({}) Locking var inner copy", self_id);
        let inner_copy = var.inner.copy.try_lock().map_err(|e| TransactionError::Blocking)?;

        let copy_lock_id = match &*inner_copy {
            Some(inner_copy) => match &inner_copy.locked_thread_id {
                Some(id) => id.load(Ordering::SeqCst),
                None => 0,
            },
            None => return Err(TransactionError::NoCopyPresent),
        };

        drop(inner_copy);
        info!("({}) Unlocking var inner copy", self_id);

        let self_id = self.id.load(Ordering::SeqCst);

        if self_id == copy_lock_id {
            info!("({}) Locking var inner copy", self_id);
            let inner_copy = var.inner.copy.try_lock().map_err(|e| TransactionError::Blocking)?;

            return match &*inner_copy {
                Some(guard) => {
                    let data_guard = guard.data.read().map_err(|e| TransactionError::Inner(e.to_string()))?;
                    let copied = data_guard.clone();

                    drop(data_guard);
                    drop(inner_copy);
                    info!("({}) Unlocking var inner copy", self_id);
                    Ok(ReadGuard::from_copied(copied, self))
                }
                None => Err(TransactionError::Abort),
            };
        }

        // get other context that locks the copy
        match &var.inner.ctrl {
            Some(control) => {
                info!("({}) Locking control contexts", self_id);
                let all_contexts = control.contexts.try_lock().map_err(|e| TransactionError::Blocking)?;
                let locking_context = match all_contexts.get(&copy_lock_id) {
                    Some(ctx) => ctx,
                    None => return Err(TransactionError::Inner("No context for locked copy found".to_string())),
                };

                let write_clock = locking_context.write_clock.load(Ordering::SeqCst);
                let local_clock = self.local_clock.load(Ordering::SeqCst);

                // info!("({}) Unlocking control contexts", self_id);
                // drop(locking_context);

                // check for stealing
                if write_clock <= local_clock {
                    info!("({}) Locking inner copy contexts", self_id);
                    let inner_copy = var.inner.copy.try_lock().map_err(|e| TransactionError::Blocking)?;

                    match &*inner_copy {
                        Some(inner) => {
                            info!("({}) Locking inner copy's data", self_id);

                            let data_guard = inner.data.read().map_err(|e| TransactionError::Inner(e.to_string()))?;
                            let copied = data_guard.clone();

                            info!("({}) unlocking inner copy's data", self_id);
                            drop(data_guard);
                            info!("({}) Unlocking inner copy contexts", self_id);
                            drop(inner_copy);

                            return Ok(ReadGuard::from_copied(copied, self));
                        }
                        None => return Err(TransactionError::NoCopyPresent),
                    };
                }
            }
            None => return Err(TransactionError::Inner("No inner controller present".to_string())),
        }

        Ok(ReadGuard::from_baseguard(inner_data, self))
    }

    /// tries to lock current variable
    pub fn try_lock<'a>(&'a self, var: &'a RLUVar<T>) -> Result<WriteGuard<'a, T>> {
        self.set_writer();

        // get actual object
        let inner = &var.inner;

        // get self id
        let self_id = self.id.load(Ordering::SeqCst);

        if var.is_locked() {
            info!("({}) Locking inner copy data", self_id);
            let copy_guard = inner.copy.try_lock().map_err(|e| TransactionError::Blocking)?;

            let copy = match &*copy_guard {
                Some(copy_ptr) => copy_ptr,
                None => return Err(TransactionError::Failed),
            };

            let copy_thread_id = match &copy.locked_thread_id {
                Some(thread_id) => thread_id.load(Ordering::SeqCst),
                None => return Err(TransactionError::Failed),
            };

            if copy_thread_id == self_id {
                match &*copy_guard {
                    Some(copy) => {
                        let mut mutex_guard = copy.data.write().expect("msg");
                        let copied = mutex_guard.deref_mut().clone();
                        drop(mutex_guard);

                        return Ok(WriteGuard::from_guard_copy(
                            copy_guard,
                            copied,
                            self,
                            Some(var.inner.clone()),
                        ));
                    }
                    None => {
                        self.abort();
                        return Err(TransactionError::NoCopyPresent);
                    }
                };
            }
        }

        info!("({}) Locking inner data", self_id);
        let data = inner
            .deref()
            .data
            .try_lock()
            .map_err(|e| TransactionError::Blocking)?
            .clone();

        info!("({}) Unlocking inner data", self_id);

        let copy = InnerVarCopy {
            data: Arc::new(RwLock::new(data.clone())),
            locked_thread_id: Some(AtomicUsize::new(self_id)),
            original: var.inner.clone(),
        };

        info!("({}) Locking inner copy data", self_id);
        let mut copy_guard = inner.copy.try_lock().map_err(|e| TransactionError::Blocking)?;
        // update var to point to copy
        copy_guard.replace(copy);

        return Ok(WriteGuard::from_guard_copy(
            copy_guard,
            data,
            self,
            Some(var.inner.clone()),
        ));
    }

    fn synchronize(&self) -> Result<()> {
        let self_id = self.id.load(Ordering::SeqCst);
        info!("({}) Locking controller contexts data", self_id);

        // CHANGED FROM TRY_LOCK TO LOCK
        let contexts = match self.ctrl.contexts.lock().map_err(|e| TransactionError::Blocking) {
            Ok(guard) => guard,
            Err(err) => {
                panic!("({}) Unlocking context failed", self_id);
                // return Err(TransactionError::Blocking);
            }
        };

        info!("({}) Locking sync counts contexts data", self.id.load(Ordering::SeqCst));

        // sychronize with other contexts, collect their run stats
        // CHANGED FROM TRY_LOCK TO LOCK
        let mut sync_count = match self.sync_count.lock().map_err(|e| TransactionError::Blocking) {
            Ok(guard) => guard,
            Err(err) => {
                panic!("({}) Synchronize. Unlocking sync count failed", self_id);
                // return Err(TransactionError::Blocking);
            }
        };

        for (id, ctx) in contexts.deref() {
            let id = ctx.id.load(Ordering::SeqCst);

            if id == self_id {
                info!(
                    "({}) skip own context, but run_count would be ({})",
                    self_id,
                    ctx.run_count.load(Ordering::SeqCst)
                );
                continue;
            }
            let run_count = ctx.run_count.load(Ordering::SeqCst);

            sync_count.deref_mut().insert(id, run_count);
        }

        // info!("sync counts for id {} = {:?}", self_id, sync_count);

        info!("({}) synchronize begin: Unlocking controller contexts data", self_id);
        drop(contexts);

        info!("({}) Locking controller contexts data", self_id);
        // CHANGED FROM TRY_LOCK TO LOCK
        let contexts = match self.ctrl.contexts.lock().map_err(|e| TransactionError::Blocking) {
            Ok(guard) => guard,
            Err(err) => {
                panic!("({}) Synchronize. Unlocking context failed", self_id);
                // return Err(TransactionError::Blocking);
            }
        };

        // debug
        let mut num_rounds = 0;
        let max_rounds = 20;

        // wait for other contexts
        for (id, ctx) in contexts.deref() {
            loop {
                if sync_count.get(id).is_none() {
                    break;
                }

                let ctx_run_count = ctx.run_count.load(Ordering::SeqCst);
                let write_clock = self.write_clock.load(Ordering::SeqCst);
                let local_clock = ctx.local_clock.load(Ordering::SeqCst);

                info!(
                    "({}) SYNC: sync count id {}: value {}, write_clock {}, local_clock {}, context run count : {}",
                    self_id, id, sync_count[id], write_clock, local_clock, ctx_run_count
                );

                if (sync_count[id] & 0x1) == 0 {
                    // is inactive
                    break;
                }
                if sync_count[id] != ctx_run_count {
                    // has progressed
                    break;
                }

                if write_clock <= local_clock {
                    // started after this context
                    break;
                }

                num_rounds += 1;
                if num_rounds > max_rounds {
                    return Ok(());
                }

                // put cpu hint to tell system scheduler make efficient use of idle time
                core::hint::spin_loop();
            }
        }
        info!("({}) synchronize end: Unlocking controller contexts data", self_id);
        sync_count.clear();
        drop(sync_count);
        drop(contexts);

        Ok(())
    }

    fn commit_log(&self) -> Result<()> {
        self.write_clock
            .store(self.ctrl.global_count.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        self.ctrl.global_count.fetch_add(1, Ordering::SeqCst);
        self.synchronize()?;
        self.write_back_log()?;
        self.reset_write_clock();
        // fixme: missing: unlock_write_log()?
        self.swap_logs()?;

        Ok(())
    }

    fn write_back_log(&self) -> Result<()> {
        info!("({}) Locking context log", self.id.load(Ordering::SeqCst));

        // CHANGED FROM TRY_LOCK TO LOCK
        let mut guard = match self.log.lock().map_err(|e| TransactionError::Blocking) {
            Ok(guard) => guard,
            Err(err) => {
                panic!(
                    "({}) Write Back Log: Unlocking log failed",
                    self.id.load(Ordering::SeqCst)
                );
                // return Err(TransactionError::Blocking);
            }
        };

        for item in guard.deref_mut().drain().flatten() {
            item.write_back()?;
        }
        info!("({}) Unlocking context log", self.id.load(Ordering::SeqCst));
        drop(guard);

        Ok(())
    }

    fn abort(&self) {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        self.is_writer.store(false, Ordering::SeqCst)
    }

    fn reset_write_clock(&self) {
        self.write_clock.store(usize::MAX, Ordering::SeqCst);
    }

    /// Swaps the logs internally
    fn swap_logs(&self) -> Result<()> {
        info!("({}) Locking context log", self.id.load(Ordering::SeqCst));

        // CHANGED FROM TRY_LOCK TO LOCK
        let guard = match self.log.lock().map_err(|e| TransactionError::Blocking) {
            Ok(guard) => guard,
            Err(err) => {
                panic!("({}) Swap Logs: Unlocking log failed", self.id.load(Ordering::SeqCst));
                // return Err(TransactionError::Blocking);
            }
        };
        guard.deref().next();

        info!("({}) Unlocking context log", self.id.load(Ordering::SeqCst));
        drop(guard);

        Ok(())
    }
}

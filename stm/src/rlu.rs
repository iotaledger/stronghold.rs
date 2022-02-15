// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Software Transactional Memory: RLU Variant
//! ---
//! This module implements the read log update synchronization mechanism
//! to enable non-blocking concurrent reads and concurrent writes on
//! data.
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
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread_local,
};

/// Returns the calling function name
// macro_rules! caller {
//     () => {{
//         fn f() {}
//         fn type_name_of<T>(_: T) -> &'static str {
//             std::any::type_name::<T>()
//         }
//         let name = type_name_of(f);
//         &name[..name.len() - 3]
//     }};
// }

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

/// the global clock
static G_CLOCK: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // pub static Guard: Cell<HashMap<Box<dyn Future<Output = Result<(), Box<dyn Error>>>>,bool>> = Cell::new(HashMap::new());
    static GUARD: Cell<bool> = Cell::new(false);
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

/// Returns the active thread by id
fn get_rlu_context<T>(id: &usize) -> RLUContext<T>
where
    T: ReturnType,
{
    todo!()
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

    /// inidicating, if this is a copy
    copy: Arc<AtomicBool>,

    /// the current thread locking this object
    rlu_thread_id: Arc<AtomicUsize>,

    /// if this is a copy, this is the reference to the 'original'
    obj_reference: Arc<AtomicPtr<TVar<'a, T>>>,

    /// alll global related rlu objects reside here, since there are interested in synchronizing one object at a time
    global_clock: Arc<AtomicUsize>,

    /// a list of all threads monitoring this variable
    threads: Arc<Mutex<HashMap<usize, &'a RLUContext<'a, T>>>>,
}

impl<'a, T> Clone for TVar<'a, T>
where
    T: ReturnType,
{
    fn clone(&self) -> Self {
        todo!()
    }
}

impl<'a, T> TVar<'a, T>
where
    T: ReturnType,
{
    fn get_rlu_context(&self, id: &usize) -> &'a RLUContext<T> {
        self.threads.lock().expect("").get(id).unwrap()
    }
}

pub struct RLUContext<'a, T>
where
    T: ReturnType,
{
    // the thread id
    thread_id: Arc<AtomicUsize>,

    /// first write log
    w_log: Arc<AtomicPtr<TVar<'a, T>>>,

    /// second write log
    w_log_quiescence: Arc<AtomicPtr<TVar<'a, T>>>,

    // according to the paper we need a run counter
    // where even indicates a running state, and odd
    // is a rest
    running: Arc<AtomicUsize>,

    /// The local clock to decide wether to read from log, or object
    local_clock: Arc<AtomicUsize>,

    /// the write clock to signal reading from
    write_clock: Arc<AtomicUsize>,

    /// sets if writer, or not. may be obsolete
    is_writer: Arc<AtomicBool>,
}

impl<'a, T> RLUContext<'a, T>
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

    //     todo!()
    // }

    pub fn reader_lock(&self) {
        // set as reader
        self.is_writer.store(false, Ordering::Release);

        // increment number of runners. odd = running, evening = rest
        self.running
            .store(self.running.load(Ordering::Acquire) + 1, Ordering::Release);

        // update local clock
        self.local_clock
            .store(G_CLOCK.load(Ordering::Acquire), Ordering::Release)
    }

    pub fn reader_unlock(&self, var: &'a TVar<'a, T>) {
        // increment number of runners
        self.running
            .store(self.running.load(Ordering::Acquire) + 1, Ordering::Release);

        if self.is_writer.load(Ordering::Acquire) {
            self.commit_write_log(var)
        }
    }

    pub fn deref(&self, var: &'a TVar<'a, T>) -> &'a TVar<'a, T> {
        if var.copy.load(Ordering::Acquire) {
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

        let thread: &RLUContext<'a, T> = var.get_rlu_context(&thread_id);

        if self.local_clock.load(Ordering::Acquire) >= thread.write_clock.load(Ordering::Acquire) {
            return copy_ptr;
        }

        var
    }

    pub fn try_lock(&self, var: &'a TVar<'a, T>) -> *const TVar<'a, T> {
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
                return copy_ptr as *mut _;
            }

            // retry / abort
        }

        let mut copy = var.clone();

        copy.obj_reference
            .store(var as *const _ as *mut TVar<'a, T>, Ordering::Release);

        let self_thread_id = self.thread_id.load(Ordering::Acquire);
        var.rlu_thread_id.store(self_thread_id, Ordering::Release);

        //
        self.w_log.store(&mut copy, Ordering::Release);

        // TBD: try to install copy, if that fails abort

        &copy as *const _
    }

    pub fn commit_write_log(&self, var: &'a TVar<'a, T>) {
        self.write_clock
            .store(var.global_clock.load(Ordering::Acquire) + 1, Ordering::Release);

        var.global_clock.fetch_add(1, Ordering::SeqCst);
        self.synchronize(var);

        // - write back write log
        // - unlock write lock
        self.write_clock.store(usize::MAX, Ordering::Release);
        // - swap write logs
    }

    pub fn synchronize(&self, var: &'a TVar<'a, T>) {}
}

#[cfg(test)]
mod tests {

    use rand_utils::random::{string, usize};

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
        // let t: TVar<_> = TVar::new(HashMap::new(), |inner, update| inner.extend(update.into_iter()));
        // let num_threads = 4;

        // let test_values: Vec<(TVar<_>, usize, String)> =
        //     std::iter::repeat_with(|| (t.clone(), rand_usize(), rand_string()))
        //         .take(num_threads)
        //         .collect();

        // let pool = threadpool::ThreadPool::new(num_threads);

        // for _ in 0..5 {
        //     for (tcopy, id, value) in test_values.clone() {
        //         pool.execute(move || {
        //             RLUThread::with_func(|tx| {
        //                 let v = tx.read(&tcopy)?;

        //                 let mut h = v;
        //                 h.insert(id, value.clone());
        //                 tx.write(h, &tcopy)?;

        //                 // what happens, if we send an error
        //                 Ok(())
        //             })
        //             .expect("Failed");
        //         });
        //     }
        // }

        // pool.join();

        // println!("Fails {}", pool.panic_count());

        // let inner = t.lock_read().read().expect("Failed to access inner data");
        // info!("caller {}: inner: {:?}", caller!(), inner);
        // for (_, id, value) in test_values {
        //     assert!(inner.contains_key(&id));
        // }
    }
}

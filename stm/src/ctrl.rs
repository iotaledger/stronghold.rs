// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{transaction::TransactionControl, BoxedMemory, TransactionError};
use std::{
    future::Future,
    sync::{Arc, Mutex, RwLock, Weak},
};

// / This component takes in an executing future from a `Transaction` and
// / blocks further progress until it has been `awakened` again. [`Self::wake()`]
// / shall be called to  unblock the inner future.
// /
// / Since [`FutureBlocker`] is itself a future, the execution itself is non-blocking,
// / but "blocks" the inner future to make progress.
// pub struct FutureBlocker<F, T>
// where
//     F: Future,
//     T: Send + Sync + BoxedMemory,
// {
//     task: Arc<Mutex<Option<Pin<Box<F>>>>>,
//     blocked: Arc<AtomicBool>,
//     _phantom: PhantomData<T>,
// }

// impl<F, T> Clone for FutureBlocker<F, T>
// where
//     F: Future,
//     T: Send + Sync + BoxedMemory,
// {
//     fn clone(&self) -> Self {
//         Self {
//             task: self.task.clone(),
//             blocked: self.blocked.clone(),
//             _phantom: PhantomData,
//         }
//     }
// }

// impl<F, T> FutureBlocker<F, T>
// where
//     F: Future,
//     T: Send + Sync + BoxedMemory,
// {
//     pub fn new(task: F) -> Self {
//         Self {
//             task: Arc::new(Mutex::new(Some(Box::pin(task)))),
//             blocked: Arc::new(AtomicBool::new(true)),
//             _phantom: PhantomData,
//         }
//     }

//     /// Releases the underlying gate, and "wakes" the inner future
//     /// to make progress.
//     pub async fn wake(&self) {
//         self.blocked.swap(false, Ordering::Release);
//     }
// }

// impl<F, T> Future for FutureBlocker<F, T>
// where
//     F: Future<Output = Result<T, TransactionError>>,
//     T: Send + Sync + BoxedMemory,
// {
//     type Output = Result<T, TransactionError>;

//     fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
//         match self.blocked.load(Ordering::Acquire) {
//             true => {
//                 ctx.waker().to_owned().wake();
//                 Poll::Pending
//             }
//             false => {
//                 let mut lock = self.task.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;
//                 match &mut *lock {
//                     Some(ref mut inner) => {
//                         // we still need to call the waker again, until the
//                         // inner future has completed their task
//                         ctx.waker().to_owned().wake();
//                         Pin::new(inner).poll(ctx)
//                     }
//                     None => Poll::Ready(Err(TransactionError::Inner(
//                         "No future present in FutureBlock".to_string(),
//                     ))),
//                 }
//             }
//         }
//     }
// }

/// The [`MemoryController`] is being used to manage
/// many futures working on the same shared memory.
pub struct MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    /// A list of futures observing the underlying value
    futures: Arc<Mutex<Vec<Weak<F>>>>,

    // the actual value to be modified
    pub(crate) value: Arc<RwLock<Arc<T>>>,
}

impl<F, T> Clone for MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            futures: self.futures.clone(),
            value: self.value.clone(),
        }
    }
}

impl<F, T> MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    pub fn new(value: T) -> Self {
        Self {
            futures: Arc::new(Mutex::new(Vec::new())),
            value: Arc::new(RwLock::new(Arc::new(value))),
        }

        // Arc::new(mem_ctrl)
    }

    /// Garbage collect all inactive / dropped observers and keep
    /// only a list of still present ones.
    pub async fn gc(&self) -> Result<(), TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.retain(|weak_ref| weak_ref.upgrade().is_some());

        Ok(())
    }

    /// Wakes all observing futures to continue work
    pub fn wake_all(&self) -> Result<(), TransactionError> {
        let futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        for observer in futures.iter() {
            if let Some(observer) = observer.upgrade() {
                observer.wake();
            }
        }

        Ok(())
    }

    /// Adds another [`FutureBlocker`]
    pub fn push(&self, blocker: &Arc<F>) -> Result<(), TransactionError> {
        let mut futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        futures.push(Arc::downgrade(blocker));

        Ok(())
    }

    pub fn address(&self) -> usize {
        self as *const _ as usize
    }
}

impl<F, T> PartialEq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        self.address().eq(&other.address())
    }
}

impl<F, T> Eq for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
}

impl<F, T> PartialOrd for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let a = self as *const _ as usize;
        let b = other as *const _ as usize;

        Some(match a {
            _ if a > b => std::cmp::Ordering::Greater,
            _ if a < b => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        })
    }
}

impl<F, T> Ord for MemoryController<F, T>
where
    F: Future + TransactionControl,
    T: Send + Sync + BoxedMemory,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self as *const _ as usize;
        let b = other as *const _ as usize;

        match a {
            _ if a > b => std::cmp::Ordering::Greater,
            _ if a < b => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

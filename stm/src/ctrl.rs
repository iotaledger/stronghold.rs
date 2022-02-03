// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{BoxedMemory, TransactionError};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};

/// This component takes in an executing future from a `Transaction` and
/// blocks further progress until it has been `awakened` again. [`Self::wake()`]
/// shall be called  
pub struct FutureBlocker<F, T>
where
    F: Future<Output = Result<T, TransactionError>>,
    T: Send + Sync + BoxedMemory,
{
    task: Arc<Mutex<Option<Pin<Box<F>>>>>,
    blocked: Arc<AtomicBool>,
}

impl<F, T> Clone for FutureBlocker<F, T>
where
    F: Future<Output = Result<T, TransactionError>>,
    T: Send + Sync + BoxedMemory,
{
    fn clone(&self) -> Self {
        Self {
            task: self.task.clone(),
            blocked: self.blocked.clone(),
        }
    }
}

impl<F, T> FutureBlocker<F, T>
where
    F: Future<Output = Result<T, TransactionError>>,
    T: Send + Sync + BoxedMemory,
{
    pub fn new(task: F) -> Self {
        Self {
            task: Arc::new(Mutex::new(Some(Box::pin(task)))),
            blocked: Arc::new(AtomicBool::new(true)),
        }
    }

    pub async fn wake(&self) {
        self.blocked.swap(false, Ordering::Release);
    }
}

impl<F, T> Future for FutureBlocker<F, T>
where
    F: Future<Output = Result<T, TransactionError>>,
    T: Send + Sync + BoxedMemory,
{
    type Output = Result<T, TransactionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.blocked.load(Ordering::Acquire) {
            true => {
                ctx.waker().to_owned().wake();
                Poll::Pending
            }
            false => {
                let mut lock = self.task.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;
                match &mut *lock {
                    Some(ref mut inner) => Pin::new(inner).poll(ctx),
                    None => Poll::Ready(Err(TransactionError::Inner(
                        "No future present in FutureBlock".to_string(),
                    ))),
                }
            }
        }
    }
}

/// The [`MemoryController`]
pub struct MemoryController<F, T>
where
    F: Future<Output = Result<T, TransactionError>>,
    T: Send + Sync + BoxedMemory,
{
    /// A list of futures observing the underlying value
    futures: Mutex<Vec<Weak<FutureBlocker<F, T>>>>,

    // the actual value to be modified
    pub(crate) value: Arc<Mutex<T>>,
}

impl<F, T> MemoryController<F, T>
where
    F: Future<Output = Result<T, TransactionError>> + Unpin,
    T: Send + Sync + BoxedMemory,
{
    pub fn new(value: T) -> Arc<Self> {
        let mem_ctrl = Self {
            futures: Mutex::new(Vec::new()),
            value: Arc::new(Mutex::new(value)),
        };

        Arc::new(mem_ctrl)
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
    pub async fn wake(&self) -> Result<(), TransactionError> {
        let futures = self
            .futures
            .lock()
            .map_err(|e| TransactionError::Inner(e.to_string()))?;

        for observer in futures.iter() {
            if let Some(observer) = observer.upgrade() {
                observer.wake().await;
            }
        }

        Ok(())
    }

    /// Adds another observing future to the vec of observers
    pub async fn push(&self, blocker: &Arc<FutureBlocker<F, T>>) -> Result<(), TransactionError> {
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
    F: Future<Output = Result<T, TransactionError>> + Unpin,
    T: Send + Sync + BoxedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        self.address().eq(&other.address())
    }
}

impl<F, T> Eq for MemoryController<F, T>
where
    F: Future<Output = Result<T, TransactionError>> + Unpin,
    T: Send + Sync + BoxedMemory,
{
}

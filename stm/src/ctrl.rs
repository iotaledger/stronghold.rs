// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{BoxedMemory, TransactionError};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};
use zeroize::Zeroize;

/// This component takes in an executing future from a `Transaction` and
/// blocks further progress.
pub struct FutureBlocker<F>
where
    F: Future,
{
    task: Arc<Mutex<Option<F>>>,
    tx: Arc<Mutex<Sender<bool>>>,
    rx: Arc<Mutex<Receiver<bool>>>,
    blocked: Arc<AtomicBool>,
}

impl<F> Clone for FutureBlocker<F>
where
    F: Future,
{
    fn clone(&self) -> Self {
        Self {
            task: self.task.clone(),
            tx: self.tx.clone(),
            rx: self.rx.clone(),
            blocked: self.blocked.clone(),
        }
    }
}

impl<F> From<F> for FutureBlocker<F>
where
    F: Future,
{
    fn from(task: F) -> Self {
        FutureBlocker::new(task)
    }
}

impl<F> FutureBlocker<F>
where
    F: Future,
{
    pub fn new(task: F) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            task: Arc::new(Mutex::new(Some(task))),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            blocked: Arc::new(AtomicBool::new(true)),
        }
    }

    pub async fn wake(&self) {
        self.tx.lock().expect("").send(false).expect("failed to send");
    }
}

impl<F> Future for FutureBlocker<F>
where
    F: Future,
{
    type Output = Result<F, TransactionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(data) = self.rx.lock().expect("").try_recv() {
            self.blocked.swap(data, Ordering::SeqCst);
        }

        match self.blocked.load(Ordering::SeqCst) {
            true => {
                ctx.waker().to_owned().wake();
                Poll::Pending
            }
            false => {
                let mut lock = self.task.lock().map_err(|e| TransactionError::Inner(e.to_string()))?;
                let task = match lock.take() {
                    Some(inner) => inner,
                    None => {
                        return Poll::Ready(Err(TransactionError::Inner(
                            "No future present in FutureBlock".to_string(),
                        )))
                    }
                };

                Poll::Ready(Ok(task))
            }
        }
    }
}

#[derive(Zeroize)]
pub struct MemoryController<F, T>
where
    T: Send + Sync + BoxedMemory,
    F: Future,
{
    /// A list of futures observing the underlying value
    futures: Mutex<Vec<Weak<FutureBlocker<F>>>>,

    // the actual value to be modified
    pub(crate) value: Arc<Mutex<T>>,
}

impl<F, T> MemoryController<F, T>
where
    T: Send + Sync + BoxedMemory,
    F: Future,
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
    pub async fn push(&self, blocker: &Arc<FutureBlocker<F>>) -> Result<(), TransactionError> {
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
    F: Future,
    T: Send + Sync + BoxedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        self.address().eq(&other.address())
    }
}

impl<F, T> Eq for MemoryController<F, T>
where
    F: Future,
    T: Send + Sync + BoxedMemory,
{
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_controller() {
        let blocker = FutureBlocker::new(async {});

        let r1 = tokio::spawn(blocker.clone());

        tokio::time::sleep(Duration::from_millis(5000)).await;
        let r2 = tokio::spawn(async move { blocker.wake().await });

        let _ = r1.await.expect("");
        r2.await.expect("");
    }
}

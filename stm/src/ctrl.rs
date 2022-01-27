// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

pub struct Blocker<F>
where
    F: Future,
{
    task: Arc<F>,
    tx: Arc<Mutex<Sender<bool>>>,
    rx: Arc<Mutex<Receiver<bool>>>,
    blocked: Arc<AtomicBool>,
}

impl<F> Clone for Blocker<F>
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

impl<F> Blocker<F>
where
    F: Future,
{
    pub fn new(ch: (Sender<bool>, Receiver<bool>), task: F) -> Self {
        Self {
            task: Arc::new(task),
            tx: Arc::new(Mutex::new(ch.0)),
            rx: Arc::new(Mutex::new(ch.1)),
            blocked: Arc::new(AtomicBool::new(true)),
        }
    }

    pub async fn wake(self) {
        self.tx.lock().expect("").send(false).expect("failed to send");
    }
}

impl<F> Future for Blocker<F>
where
    F: Future,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(data) = self.rx.lock().expect("").try_recv() {
            self.blocked.swap(data, Ordering::SeqCst);
        }

        match self.blocked.load(Ordering::SeqCst) {
            true => {
                ctx.waker().to_owned().wake();
                Poll::Pending
            }
            false => Poll::Ready(()),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_controller() {
        let blocker = Blocker::new(std::sync::mpsc::channel(), async {});

        let r1 = tokio::spawn(blocker.clone());
        let r2 = tokio::spawn(blocker.wake());

        r1.await.expect("");
        r2.await.expect("");
    }
}

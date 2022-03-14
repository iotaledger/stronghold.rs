// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::{channel::mpsc, Sink, SinkExt, Stream};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Configure how the network should behave in the case that the capacity of the [`EventChannel`] is reached, i.e. if
/// the channel is full. This is relevant in cases when the frequency of messages is larger than the frequency
/// in which the [`mpsc::Receiver`][futures::channel::mpsc::Receiver] side reads from the stream.
pub enum ChannelSinkConfig {
    /// Block until the channel has enough capacity for the new request.
    ///
    /// **Note**: This pauses all network interaction and enforces back-pressure, which may be desirable if the machine
    /// is at its limit. But it also hinders all active actions on `StrongholdP2p`, hence asynchronous methods like
    /// [`StrongholdP2p::send_request`][crate::StrongholdP2p::send_request] will be blocked as well.
    Block,
    /// New events will be dropped if the channel is full.
    DropLatest,
    /// In case that the channel is full, store new events in a ring-buffer. If the configured capacity is reached,
    /// older events will be dropped in favor of newer ones. Send the latest events sequentially in FIFO order when
    /// the channel has free capacity.
    BufferLatest,
}

/// Wrapper of a [`mpsc::channel`][futures::channel::mpsc::channel] for sending events.
/// On top of the underlying channel it allows configuration of the `Sink` behaviour if the channel
/// is full.
///
/// **Note** in case of [`ChannelSinkConfig::Block`] the [`mpsc::Receiver`] returned in [`EventChannel::new`]
/// has to be polled continuously, otherwise `StrongholdP2p` will block while the channel is full.
#[pin_project]
pub struct EventChannel<T> {
    // Actual channel
    #[pin]
    inner: mpsc::Sender<T>,
    // Queue for buffering the latest events if the channel is full.
    buffer: Option<(VecDeque<T>, usize)>,
    // Wether the `Sink` implementation of the inner channel should be used, without a buffer.
    //
    // This results in the `EventLoop` blocking until `<mpsc::Sender as Sink>::send` resolves.
    use_inner: bool,
    // Waker from `<EventChannel as Stream>::poll_next` that is notified if a new event was added to the buffer.
    waker: Option<Waker>,
}

impl<T> EventChannel<T> {
    pub fn new(capacity: usize, config: ChannelSinkConfig) -> (Self, mpsc::Receiver<T>) {
        match config {
            // Do not use a buffer, instead block according to the Sink implementation for the inner `mpsc::Sender`.
            ChannelSinkConfig::Block => {
                let (tx, rx) = mpsc::channel(capacity);
                (
                    EventChannel {
                        inner: tx,
                        buffer: None,
                        use_inner: true,
                        waker: None,
                    },
                    rx,
                )
            }
            // Do not use a buffer, drop new events if `mpsc::Sender::try_send` failed due to a full channel.
            ChannelSinkConfig::DropLatest => {
                let (inner, rx) = mpsc::channel(capacity);
                (
                    EventChannel {
                        inner,
                        buffer: None,
                        use_inner: false,
                        waker: None,
                    },
                    rx,
                )
            }
            // Use a buffer for the latest events if `mpsc::Sender::try_send` failed due to a full channel.
            ChannelSinkConfig::BufferLatest => {
                // Use capacity of 1 since the mpsc::channel only stores the first n events, rather then the last.
                // Instead use a ring-buffer with the set capacity to buffer the most recent n events.
                let (inner, rx) = mpsc::channel(0);
                (
                    EventChannel {
                        inner,
                        buffer: Some((VecDeque::with_capacity(capacity), capacity)),
                        use_inner: false,
                        waker: None,
                    },
                    rx,
                )
            }
        }
    }
}

/// Implement [`Sink`] for sending events through the underlying channel.
impl<T> Sink<T> for EventChannel<T> {
    type Error = <mpsc::Sender<T> as Sink<T>>::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.use_inner {
            self.inner.poll_ready(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        if self.use_inner {
            return self.inner.start_send(item);
        }
        let mut this = self.project();
        if let Some(waker) = this.waker.take() {
            // Inform the waker of `<Self as Stream>::poll_next` that a new event was added to the buffer.
            waker.wake()
        }
        match this.inner.try_send(item) {
            Ok(()) => Ok(()),
            Err(e) if e.is_full() => {
                // Buffer item if there is a buffer, else it is dropped.
                if let Some((ref mut buffer, capacity)) = this.buffer {
                    if buffer.len() >= *capacity {
                        // Drop older events in favor of new ones.
                        buffer.pop_front();
                    }
                    buffer.push_back(e.into_inner());
                }
                Ok(())
            }
            Err(e) => Err(e.into_send_error()),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.use_inner {
            return self.inner.poll_flush_unpin(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Implement [`Stream`] for driving the EventChannel.
///
/// If [`EventChannel`] directly blocks (flushes) on send, no polling the Stream is necessary and [`Stream::poll_next`]
/// will return `Poll::Pending` without ever notifying the waker again. If send does not block, polling the
/// `EventChannel` does the flushing of the inner channel. If there are pending events in the buffer, the inner
/// [`mpsc::Sender`] is checked. If it has the capacity for a new message, the oldest buffered event will be send.
/// If there is an empty buffer, the waker will be notified once a new event is added to the buffer.
impl<T> Stream for EventChannel<T> {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.use_inner {
            return Poll::Pending;
        }
        let mut this = self.project();
        // Flush the messages that were sent in <Self as Sink>::start_send.
        let _ = this.inner.poll_flush_unpin(cx);
        // Set the waker to be informed once a new request was added to the buffer.
        this.waker.replace(cx.waker().clone());
        // Write a message from the buffer to the channel if it has capacity.
        if let Poll::Ready(Ok(_)) = this.inner.as_mut().poll_ready(cx) {
            if let Some(msg) = this.buffer.as_mut().and_then(|b| b.0.pop_front()) {
                let _ = this.inner.as_mut().start_send(msg);
                if let Poll::Ready(Ok(_)) = this.inner.as_mut().poll_flush_unpin(cx) {
                    return Poll::Ready(Some(()));
                }
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod test {
    use futures::{FutureExt, StreamExt};
    use std::time::Duration;
    use tokio::time::sleep;

    use stronghold_utils::random;

    use super::*;

    const TEST_BUF_SIZE: usize = 5;
    const TEST_DATA_COUNT: usize = 10;

    fn test_vec() -> Vec<Vec<u8>> {
        let mut data = Vec::with_capacity(TEST_DATA_COUNT);
        for _ in 0..data.capacity() {
            let v = random::bytestring(32);
            data.push(v)
        }
        data
    }

    async fn send(data: Vec<Vec<u8>>, tx: &mut EventChannel<Vec<u8>>) -> Result<(), ()> {
        let do_send = async {
            for msg in data {
                tx.send(msg).await.unwrap();
            }
        };

        futures::select! {
            _ = do_send.fuse() => Ok(()),
            _ =  sleep(Duration::from_secs(2)).fuse() =>  {
                Err(())
            },
        }
    }

    async fn receive(rx: &mut mpsc::Receiver<Vec<u8>>, count: usize) -> Result<Vec<Vec<u8>>, ()> {
        let mut received = Vec::new();
        let do_receive = async {
            for _ in 0..count {
                let item = rx.next().await.unwrap();
                received.push(item)
            }
        };

        futures::select! {
            _ = do_receive.fuse() => {},
            _ =  sleep(Duration::from_secs(2)).fuse() => {
                return Err(())
            }
        }
        assert!(rx.next().now_or_never().is_none());
        Ok(received)
    }

    #[tokio::test]
    async fn drop_latest_channel() {
        let data = test_vec();
        let (mut tx, mut rx) = EventChannel::new(TEST_BUF_SIZE, ChannelSinkConfig::DropLatest);
        send(data.clone(), &mut tx).await.expect("Send Blocked");
        tokio::spawn(async move {
            loop {
                let _ = tx.next().await;
            }
        });
        let received = receive(&mut rx, TEST_BUF_SIZE + 1).await.expect("Receive Blocked");
        assert_eq!(received[..], data[..TEST_BUF_SIZE + 1])
    }

    #[tokio::test]
    async fn buffered_channel() {
        let data = test_vec();
        let (mut tx, mut rx) = EventChannel::new(TEST_BUF_SIZE, ChannelSinkConfig::BufferLatest);
        send(data.clone(), &mut tx).await.expect("Send Blocked");
        tokio::spawn(async move {
            loop {
                let _ = tx.next().await;
            }
        });
        let received = receive(&mut rx, TEST_BUF_SIZE + 1).await.expect("Receive Blocked");
        let mut received_iter = received.into_iter();
        let first = received_iter.next().unwrap();
        assert_eq!(first, data[0]);

        assert_eq!(
            received_iter.collect::<Vec<_>>()[..],
            data[TEST_DATA_COUNT - TEST_BUF_SIZE..]
        )
    }

    #[tokio::test]
    async fn block_channel_with_backpressure() {
        let data = test_vec();
        let (mut tx, mut rx) = EventChannel::new(TEST_BUF_SIZE, ChannelSinkConfig::Block);

        let mut first = data.clone();
        let second = first.split_off(TEST_BUF_SIZE);
        let mut received: Vec<Vec<u8>> = Vec::new();
        for batch in [first, second] {
            send(batch, &mut tx).await.expect("Send Blocked");

            loop {
                futures::select! {
                    _ = tx.next().fuse() => {},
                    r = receive(&mut rx, TEST_BUF_SIZE).fuse() => {
                        received.append(&mut r.expect("Receive Blocked"));
                        break
                    },
                }
            }
        }
        assert_eq!(received, data)
    }

    #[tokio::test]
    #[should_panic(expected = "Send Blocked")]
    async fn block_channel_without_backpressure() {
        let data = test_vec();
        let (mut tx, _rx) = EventChannel::new(TEST_BUF_SIZE, ChannelSinkConfig::Block);
        send(data.clone(), &mut tx).await.expect("Send Blocked");
    }
}

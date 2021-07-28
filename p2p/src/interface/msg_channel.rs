// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::{channel::mpsc, Sink, SinkExt, Stream};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Configure how the network should behave in the case that the capacity of the [`EventChannel`] is reached, i.g. if
/// the channel is full. This is relevant in cases when the frequency of messages is larger than the frequency
/// in which the [`mpsc::Receiver`][futures::channel::mpsc::Receiver] side reads from the stream.
pub enum ChannelSinkConfig {
    /// Block until the channel has enough capacity for the new request.
    ///
    /// **Note**: This pauses all network interaction and enforces back-pressure, which may be desirable if the machine
    /// is at its limit. But it also hinders all active actions on `StrongholdP2p`, hence asynchronous methods like
    /// [`StrongholdP2p::send_request`][super::StrongholdP2p::send_request] will be blocked as well.
    Block,
    /// New events will be dropped if the channel is full.
    DropLatest,
    /// In case that the channel is full, store new events in a ring-buffer. If the configured capacity is reached,
    /// older events will be dropped in favor of newer ones. Send the latest events sequentially in FIFO order when
    /// the channel has free capacity.
    BufferLatest,
}

/// Wrapper of a [`mpsc::channel`][futures::channel::mpsc::channel] for sending events.
/// The [`EventChannel`] cen be configure its behaviour e capacity of the channel is reached.
pub struct EventChannel<T> {
    // Actual channel
    inner: mpsc::Sender<T>,
    // Queue for buffering the latest events if the channel is full.
    buffer: Option<VecDeque<T>>,
    // Wether the `Sink` implementation of the inner channel should be used, without a buffer.
    //
    // This results in the `SwarmTask` blocking until `<mpsc::Sender as Sink>::send` resolves.
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
                let (inner, rx) = mpsc::channel(1);
                (
                    EventChannel {
                        inner,
                        buffer: Some(VecDeque::with_capacity(capacity)),
                        use_inner: false,
                        waker: None,
                    },
                    rx,
                )
            }
        }
    }
}

impl<T> Unpin for EventChannel<T> {}

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
            let res = self.inner.start_send(item);
            return res;
        }
        match self.inner.try_send(item) {
            Ok(()) => Ok(()),
            Err(e) if e.is_full() => match self.buffer.as_mut() {
                Some(buffer) => {
                    if buffer.len() >= buffer.capacity() {
                        // Drop older events in favor of new ones.
                        buffer.pop_front();
                    }
                    buffer.push_back(e.into_inner());
                    if let Some(waker) = self.waker.as_ref() {
                        // Inform the waker of `<Self as Stream>::poll_next` that a new event was added to the buffer.
                        waker.wake_by_ref()
                    }
                    Ok(())
                }
                None => Ok(()),
            },
            Err(e) => Err(e.into_send_error()),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(buf) = self.buffer.as_mut() {
            buf.clear();
        }
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Implement [`Stream`] for driving the EventChannel.
///
/// If there is no buffer, [`Stream::poll_next`] will return `Poll::Pending` without ever notifying the waker again.  
/// If there are pending events in the buffer, the inner [`mpsc::Sender`] is checked. If it has the capacity for a new
/// message, the oldest buffered event will be send.
/// If there is an empty buffer, the waker will be notified once a new event is added to the buffer.
impl<T> Stream for EventChannel<T> {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.buffer.as_ref() {
            Some(b) if b.is_empty() => {
                // Set the waker to be informed once a new request was added to the buffer.
                self.waker.replace(cx.waker().clone());
                return Poll::Pending;
            }
            None => return Poll::Pending,
            _ => {}
        }
        // Check if the channel is now ready to receive a new event.
        if let Poll::Ready(Ok(_)) = self.inner.poll_ready(cx) {
            // Send the oldest message from the buffer.
            // The unwrap will never panic since it was checked that the buffer exists and is not empty.
            let msg = self.buffer.as_mut().and_then(|b| b.pop_front()).unwrap();
            let _ = self.inner.start_send(msg);
            Poll::Ready(Some(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T> Drop for EventChannel<T> {
    fn drop(&mut self) {
        self.inner.close_channel();
    }
}

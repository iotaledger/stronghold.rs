// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum BusyBreakerError {
    #[error("number of allowed breaker trips exceeds configuration")]
    BreakerTripsExceeded,
}

/// # BusyBreaker
/// [`BusyBreaker`] is kind of a circuit-breaker and busy keeper for short delays on spin loops on the CPU.
///
/// # Example
pub struct BusyBreaker {
    max: AtomicUsize,
    unit: AtomicUsize,
}

impl Default for BusyBreaker {
    fn default() -> Self {
        // 7 shifts may be a sensible default
        Self::new(7)
    }
}

impl Clone for BusyBreaker {
    fn clone(&self) -> Self {
        Self {
            unit: AtomicUsize::new(self.unit.load(Ordering::Acquire)),
            max: AtomicUsize::new(self.max.load(Ordering::Acquire)),
        }
    }
}

impl BusyBreaker {
    /// Creates a new [`BusyBreaker`] with a configurable number
    /// of exponential trips before the breaker trips. In the latter
    /// case an error is being returned.
    pub fn new(max_trips: usize) -> Self {
        Self {
            unit: AtomicUsize::new(0),
            max: AtomicUsize::new(max_trips),
        }
    }

    /// Keeps the CPU busy but hints to the CPU reschedule the CPU time
    ///
    /// [`core::hint::spin_loop()`] may be available on the integrating system,
    /// otherwise this function call is just a busy loop, that wastes some CPU cycles
    pub fn spin(&self) -> Result<(), BusyBreakerError> {
        match self.unit.load(Ordering::Acquire) {
            unit if unit <= self.max.load(Ordering::Acquire) => {
                for _ in 0..(1 << unit) {
                    core::hint::spin_loop();
                }
                self.unit.store(unit + 1, Ordering::Release);

                Ok(())
            }
            _ => Err(BusyBreakerError::BreakerTripsExceeded),
        }
    }

    /// Resets the breaker to zero
    pub fn reset(&self) {
        self.unit.store(0, Ordering::Release);
    }
}

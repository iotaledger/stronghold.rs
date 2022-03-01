// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::atomic::{AtomicUsize, Ordering},
};

const MAX_WAIT_UNITS: usize = 7;

/// # BusyBreaker
/// [`BusyBreaker`] is kind of a circuit-breaker and busy keeper for short delays on spin loops on the CPU.
///
/// # Example
#[derive(Default)]
pub struct BusyBreaker {
    unit: AtomicUsize,
}

impl BusyBreaker {
    /// Keeps the CPU busy but hints to the CPU reschedule the CPU time
    ///
    /// [`core::hint::spin_loop()`] may be available on the integrating system,
    /// otherwise this function call is just a busy loop, that wastes some CPU cycles
    pub fn spin(&self) -> Result<(), Box<dyn Error>> {
        match self.unit.load(Ordering::Acquire) {
            unit if unit <= MAX_WAIT_UNITS => {
                for _ in 0..(1 << unit) {
                    core::hint::spin_loop();
                }
                self.unit.store(unit + 1, Ordering::Release);

                Ok(())
            }
            _ => Err("Reacher maximum units".into()),
        }
    }

    /// Resets the breaker to zero
    pub fn reset(&self) {
        self.unit.store(0, Ordering::Release);
    }
}

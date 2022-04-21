// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "std")]
mod stronghold_test_std {}

#[cfg(feature = "p2p")]
mod stronghold_test_p2p {}

#[cfg(test)]
mod dispatch_mapper;

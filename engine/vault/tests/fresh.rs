// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use test_utils::fresh::*;

use secret::X25519XChacha20Poly1305;

use rand::Rng;

pub fn keypair() -> (X25519XChacha20Poly1305::PrivateKey, X25519XChacha20Poly1305::PublicKey) {
    X25519XChacha20Poly1305::keypair().unwrap()
}

pub fn recipient() -> vault::Recipient {
    keypair().1
}

pub fn record_hint() -> vault::RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
    bs.into()
}

// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use test_utils::fresh::*;

use runtime::guarded::r#box::GuardedBox;

use rand::Rng;

pub fn keypair() -> (GuardedBox<vault::RecipientKey>, vault::Recipient) {
    let (k, r) = vault::recipient_keypair().unwrap();
    (GuardedBox::new(k).unwrap(), r)
}

pub fn recipient() -> vault::Recipient {
    keypair().1
}

pub fn record_hint() -> vault::RecordHint {
    let mut bs = [0; 24];
    rand::thread_rng().fill(&mut bs);
    bs.into()
}

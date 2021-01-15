// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::ActorSystem;

use crate::{ProcResult, Procedure, ResultMessage, SLIP10DeriveInput, StatusMessage, Stronghold};

use super::fresh;

fn setup_stronghold() -> (Vec<u8>, Stronghold) {
    let sys = ActorSystem::new().unwrap();

    let cp = fresh::bytestring();

    let s = Stronghold::init_stronghold_system(sys, cp.clone(), vec![]);
    (cp, s)
}

#[test]
fn usecase_ed25519() {
    let (_cp, sh) = setup_stronghold();

    let seed = fresh::location();

    if fresh::coinflip() {
        let size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };

        match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Generate {
            size_bytes,
            output: seed.clone(),
            hint: fresh::record_hint(),
        })) {
            ProcResult::SLIP10Generate(ResultMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }
    } else {
        match futures::executor::block_on(sh.runtime_exec(Procedure::BIP39Generate {
            passphrase: fresh::passphrase(),
            output: seed.clone(),
            hint: fresh::record_hint(),
        })) {
            ProcResult::BIP39Generate(ResultMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }
    }

    let (_path, chain) = fresh::hd_path();
    let key = fresh::location();

    match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
        chain,
        input: SLIP10DeriveInput::Seed(seed),
        output: key.clone(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Derive(StatusMessage::Ok(())) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let pk = match futures::executor::block_on(sh.runtime_exec(Procedure::Ed25519PublicKey {
        private_key: key.clone(),
    })) {
        ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk)) => pk,
        r => panic!("unexpected result: {:?}", r),
    };

    let msg = fresh::bytestring();

    let sig = match futures::executor::block_on(sh.runtime_exec(Procedure::Ed25519Sign {
        private_key: key,
        msg: msg.clone(),
    })) {
        ProcResult::Ed25519Sign(ResultMessage::Ok(sig)) => sig,
        r => panic!("unexpected result: {:?}", r),
    };

    {
        use crypto::ed25519::{verify, PublicKey, Signature};
        let pk = PublicKey::from_compressed_bytes(pk).unwrap();
        let sig = Signature::from_bytes(sig);
        assert!(verify(&pk, &sig, &msg));
    }
}

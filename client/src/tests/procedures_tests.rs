// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use riker::actors::ActorSystem;

use crate::{ProcResult, Procedure, ResultMessage, SLIP10Curve, SLIP10DeriveInput, Stronghold};

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

    let (_path, chain) = fresh::slip10_hd_chain();
    let key = fresh::location();

    match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
        curve: SLIP10Curve::Ed25519,
        chain,
        input: SLIP10DeriveInput::Seed(seed),
        output: key.clone(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => (),
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
        use crypto::signatures::ed25519::{PublicKey, Signature};
        let pk = PublicKey::try_from_bytes(pk).unwrap();
        let sig = Signature::from_bytes(sig);
        assert!(pk.verify(&sig, &msg));
    }
}

#[test]
fn usecase_secp256k1_ecdsa() {
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

    let (_path, chain) = fresh::slip10_hd_chain();
    let key = fresh::location();

    match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
        curve: SLIP10Curve::Secp256k1,
        chain,
        input: SLIP10DeriveInput::Seed(seed),
        output: key.clone(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let pk = match futures::executor::block_on(sh.runtime_exec(Procedure::Secp256k1EcdsaPublicKey {
        private_key: key.clone(),
    })) {
        ProcResult::Secp256k1EcdsaPublicKey(ResultMessage::Ok(pk)) => pk,
        r => panic!("unexpected result: {:?}", r),
    };

    let evm_address = match futures::executor::block_on(sh.runtime_exec(Procedure::Secp256k1EcdsaEvmAddress {
        private_key: key.clone(),
    })) {
        ProcResult::Secp256k1EcdsaEvmAddress(ResultMessage::Ok(evm_address)) => evm_address,
        r => panic!("unexpected result: {:?}", r),
    };

    let msg = fresh::bytestring();

    let sig = match futures::executor::block_on(sh.runtime_exec(Procedure::Secp256k1EcdsaSign {
        private_key: key,
        msg: msg.clone(),
    })) {
        ProcResult::Secp256k1EcdsaSign(ResultMessage::Ok(sig)) => sig,
        r => panic!("unexpected result: {:?}", r),
    };

    {
        use crypto::signatures::secp256k1_ecdsa::{PublicKey, Signature};
        let pk = PublicKey::try_from_bytes(&pk).unwrap();
        let sig = Signature::try_from_bytes(&sig).unwrap();
        assert!(pk.verify(&sig, &msg));
        assert_eq!(pk.to_evm_address(), evm_address.into());
    }
}

#[test]
fn usecase_SLIP10Derive_intermediate_keys() {
    let (_cp, sh) = setup_stronghold();

    let seed = fresh::location();

    match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Generate {
        size_bytes: None,
        output: seed.clone(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let (_path, chain0) = fresh::slip10_hd_chain();
    let (_path, chain1) = fresh::slip10_hd_chain();

    let cc0 = match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
        curve: SLIP10Curve::Ed25519,
        chain: [chain0.clone(), chain1.clone()].concat(),
        input: SLIP10DeriveInput::Seed(seed.clone()),
        output: fresh::location(),
        hint: fresh::record_hint(),
    })) {
        ProcResult::SLIP10Derive(ResultMessage::Ok(cc)) => cc,
        r => panic!("unexpected result: {:?}", r),
    };

    let cc1 = {
        let intermediate = fresh::location();

        match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
            curve: SLIP10Curve::Ed25519,
            chain: chain0,
            input: SLIP10DeriveInput::Seed(seed),
            output: intermediate.clone(),
            hint: fresh::record_hint(),
        })) {
            ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => (),
            r => panic!("unexpected result: {:?}", r),
        };

        match futures::executor::block_on(sh.runtime_exec(Procedure::SLIP10Derive {
            curve: SLIP10Curve::Ed25519,
            chain: chain1,
            input: SLIP10DeriveInput::Key(intermediate),
            output: fresh::location(),
            hint: fresh::record_hint(),
        })) {
            ProcResult::SLIP10Derive(ResultMessage::Ok(cc)) => cc,
            r => panic!("unexpected result: {:?}", r),
        }
    };

    assert_eq!(cc0, cc1);
}

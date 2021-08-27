// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use std::sync::{Arc, Mutex};

use crypto::signatures::ed25519::{PublicKey, Signature};

use super::fresh;
use crate::{
    procedures::{
        BIP39Generate, Ed25519PublicKey, Ed25519Sign, GetTargetVault, ProcCombine, SLIP10Derive, Slip10Generate,
    },
    SLIP10DeriveInput, Stronghold,
};

async fn setup_stronghold() -> (Vec<u8>, Stronghold) {
    let cp = fresh::bytestring();

    let s = Stronghold::init_stronghold_system(cp.clone(), vec![]).await.unwrap();
    (cp, s)
}

#[actix::test]
async fn usecase_ed25519() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    if fresh::coinflip() {
        let size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };

        match sh
            .runtime_exec(
                Slip10Generate {
                    size_bytes,
                    output: (seed.clone(), fresh::record_hint()),
                }
                .build(),
            )
            .await
        {
            Ok(()) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    } else {
        match sh
            .runtime_exec(
                BIP39Generate {
                    passphrase: fresh::passphrase(),
                    output: (seed.clone(), fresh::record_hint()),
                }
                .build(),
            )
            .await
        {
            Ok(()) => (),
            Err(err) => panic!("unexpected error: {:?}", err),
        }
    }

    let (_path, chain) = fresh::hd_path();
    let key = fresh::location();

    match sh
        .runtime_exec(
            SLIP10Derive {
                chain,
                input: SLIP10DeriveInput::Seed(seed),
                output: (key.clone(), fresh::record_hint()),
            }
            .build(),
        )
        .await
    {
        Ok(_) => (),
        Err(err) => panic!("unexpected error: {:?}", err),
    };

    let pk = match sh
        .runtime_exec(
            Ed25519PublicKey {
                private_key: key.clone(),
            }
            .build(),
        )
        .await
    {
        Ok(pk) => pk,
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let msg = fresh::bytestring();

    let sig = match sh
        .runtime_exec(
            Ed25519Sign {
                private_key: key,
                msg: msg.clone(),
            }
            .build(),
        )
        .await
    {
        Ok(sig) => sig,
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    {
        use crypto::signatures::ed25519::{PublicKey, Signature};

        let pk = PublicKey::try_from_bytes(pk).unwrap();
        let sig = Signature::from_bytes(sig);
        assert!(pk.verify(&sig, &msg));
    }
}

#[actix::test]
async fn usecase_ed25519_as_complex() {
    let (_cp, sh) = setup_stronghold().await;

    let msg = fresh::bytestring();

    let generate = Slip10Generate {
        size_bytes: fresh::coinflip().then(|| fresh::usize(1024)),
        output: (fresh::location(), fresh::record_hint()),
    };

    let derive = SLIP10Derive {
        chain: fresh::hd_path().1,
        input: SLIP10DeriveInput::Seed(generate.get_target_location()),
        output: (fresh::location(), fresh::record_hint()),
    };

    let get_pk = Ed25519PublicKey {
        private_key: derive.get_target_location(),
    };

    let sign = Ed25519Sign {
        private_key: derive.get_target_location(),
        msg: msg.clone(),
    };

    let pub_key_arc = Arc::new(Mutex::new(None));
    let pub_key_arc_clone = pub_key_arc.clone();

    let combined_proc = generate
        .and_then(derive)
        .drop_output()
        .and_then(get_pk)
        .map_output(move |pk| {
            let mut pub_key = pub_key_arc_clone.lock().unwrap();
            pub_key.replace(pk);
        })
        .and_then(sign)
        .build();

    let sig = sh.runtime_exec(combined_proc).await.unwrap();

    let pub_key = pub_key_arc.lock().unwrap();
    let pk = PublicKey::try_from_bytes(pub_key.unwrap()).unwrap();
    let sig = Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));
}

#[actix::test]
async fn usecase_SLIP10Derive_intermediate_keys() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    match sh
        .runtime_exec(
            Slip10Generate {
                size_bytes: None,
                output: (seed.clone(), fresh::record_hint()),
            }
            .build(),
        )
        .await
    {
        Ok(()) => (),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0 = match sh
        .runtime_exec(
            SLIP10Derive {
                chain: chain0.join(&chain1),
                input: SLIP10DeriveInput::Seed(seed.clone()),
                output: (fresh::location(), fresh::record_hint()),
            }
            .build(),
        )
        .await
    {
        Ok(cc) => cc,
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let cc1 = {
        let intermediate = fresh::location();

        match sh
            .runtime_exec(
                SLIP10Derive {
                    chain: chain0,
                    input: SLIP10DeriveInput::Seed(seed),
                    output: (intermediate.clone(), fresh::record_hint()),
                }
                .build(),
            )
            .await
        {
            Ok(_) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        match sh
            .runtime_exec(
                SLIP10Derive {
                    chain: chain1,
                    input: SLIP10DeriveInput::Key(intermediate),
                    output: (fresh::location(), fresh::record_hint()),
                }
                .build(),
            )
            .await
        {
            Ok(cc) => cc,
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    };

    assert_eq!(cc0, cc1);
}

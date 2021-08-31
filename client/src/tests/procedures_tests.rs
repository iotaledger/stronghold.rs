// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use std::sync::{Arc, Mutex};

use super::fresh;
use crate::{procedures::*, SLIP10DeriveInput, Stronghold};
use crypto::{
    hashes::sha::{SHA256, SHA256_LEN},
    signatures::ed25519::{self, PublicKey, Signature},
};
use engine::runtime::GuardedVec;

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
        .then(derive)
        .drop_output()
        .then(get_pk)
        .map_output(move |pk| {
            let mut pub_key = pub_key_arc_clone.lock().unwrap();
            pub_key.replace(pk);
        })
        .then(sign)
        .build();

    let sig = sh.runtime_exec(combined_proc).await.unwrap();

    let pub_key = pub_key_arc.lock().unwrap();
    let pk = PublicKey::try_from_bytes(pub_key.unwrap()).unwrap();
    let sig = Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));
}

#[actix::test]
async fn usecase_collection_of_data() {
    let (_cp, sh) = setup_stronghold().await;

    let key = {
        let mut seed = Slip10Generate {
            size_bytes: fresh::coinflip().then(|| fresh::usize(1024)),
            output: (fresh::location(), fresh::record_hint()),
        }
        .generate()
        .unwrap()
        .write_vault;
        SLIP10Derive {
            chain: fresh::hd_path().1,
            input: SLIP10DeriveInput::Seed(fresh::location()),
            output: (fresh::location(), fresh::record_hint()),
        }
        .process(GuardedVec::from(seed.as_mut_slice()))
        .unwrap()
        .write_vault
    };

    // test sign and hash

    fn digest(data: &[u8]) -> [u8; SHA256_LEN] {
        let mut digest = [0; SHA256_LEN];
        SHA256(data, &mut digest);
        digest
    }

    let messages = vec![Vec::from("msg1"), Vec::from("msg2"), Vec::from("msg3")];

    let expected = messages
        .clone()
        .into_iter()
        .map(|vec| {
            let mut raw = key.to_vec();
            raw.truncate(32);
            let mut bs = [0; 32];
            bs.copy_from_slice(&raw);

            let sk = ed25519::SecretKey::from_bytes(bs);

            let sig = sk.sign(&vec).to_bytes();
            digest(&sig)
        })
        .filter(|bytes| bytes.iter().any(|b| b <= &10u8))
        .fold(Vec::new(), |mut acc, curr| {
            acc.extend_from_slice(&curr);
            acc
        });

    // write seed to vault
    let key_location = fresh::location();
    let write_vault_proc = Input { data: key }.write_output(key_location.clone(), fresh::record_hint());
    sh.runtime_exec(write_vault_proc.build()).await.unwrap();

    // test procedure
    let ed25519_sign = Ed25519SignDyn {
        private_key: key_location.clone(),
    };
    let sign_and_hash_vec = ed25519_sign.map_output(|signed| digest(&signed)).on_vec();
    let proc = sign_and_hash_vec
        .input(messages)
        .map_output(|vec| {
            vec.into_iter()
                .filter(|bytes| bytes.iter().any(|b| b <= &10u8))
                .fold(Vec::new(), |mut acc, curr| {
                    acc.extend_from_slice(&curr);
                    acc
                })
        })
        .build();
    let out = sh.runtime_exec(proc).await.unwrap();
    assert_eq!(out, expected);
}

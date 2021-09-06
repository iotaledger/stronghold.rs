// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crypto::signatures::ed25519::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use super::fresh;
use crate::{procedures::*, Stronghold};
// use crypto::{
//     hashes::sha::{SHA256, SHA256_LEN},
//     signatures::ed25519::{self, PublicKey, Signature},
// };
use std::convert::TryInto;
// use engine::runtime::GuardedVec;

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
        let slip10_generate = Slip10Generate::new(size_bytes).write_secret(seed.clone(), fresh::record_hint());

        match sh.runtime_exec(slip10_generate.build()).await {
            Ok(_) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    } else {
        let bip32_gen = BIP39Generate::new(fresh::passphrase()).write_secret(seed.clone(), fresh::record_hint());
        match sh.runtime_exec(bip32_gen.build()).await {
            Ok(_) => (),
            Err(err) => panic!("unexpected error: {:?}", err),
        }
    }

    let (_path, chain) = fresh::hd_path();
    let key = fresh::location();

    let slip10_derive = SLIP10Derive::new_from_seed(seed, chain).write_secret(key.clone(), fresh::record_hint());
    match sh.runtime_exec(slip10_derive.build()).await {
        Ok(_) => (),
        Err(err) => panic!("unexpected error: {:?}", err),
    };

    let k = DataKey::new("key1");
    let ed25519_pk = Ed25519PublicKey::new(key.clone()).store_output(k.clone());
    let pk = match sh.runtime_exec(ed25519_pk.build()).await {
        Ok(data) => data.get(&k).cloned().unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let msg = fresh::bytestring();

    let k = DataKey::new("key2");
    let ed25519_sign = Ed25519Sign::new(key, msg.clone()).store_output(k.clone());
    let sig = match sh.runtime_exec(ed25519_sign.build()).await {
        Ok(data) => data.get(&k).cloned().unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    {
        use crypto::signatures::ed25519::{PublicKey, Signature};

        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.try_into().unwrap();
        let pk = PublicKey::try_from_bytes(pk_bytes).unwrap();
        let sig_bytes: [u8; SIGNATURE_LENGTH] = sig.try_into().unwrap();
        let sig = Signature::from_bytes(sig_bytes);
        assert!(pk.verify(&sig, &msg));
    }
}

#[actix::test]
async fn usecase_SLIP10Derive_intermediate_keys() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    let slip10_generate = Slip10Generate::new(None).write_secret(seed.clone(), fresh::record_hint());
    match sh.runtime_exec(slip10_generate.build()).await {
        Ok(_) => (),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0 = {
        let k = DataKey::new("key3");
        let slip10_derive = SLIP10Derive::new_from_seed(seed.clone(), chain0.join(&chain1)).store_output(k.clone());

        match sh.runtime_exec(slip10_derive.build()).await {
            Ok(data) => data.get(&k).cloned().unwrap(),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    };

    let cc1 = {
        let intermediate = fresh::location();

        let slip10_derive_intermediate =
            SLIP10Derive::new_from_seed(seed, chain0).write_secret(intermediate.clone(), fresh::record_hint());

        match sh.runtime_exec(slip10_derive_intermediate.build()).await {
            Ok(_) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        let k = DataKey::new("key4");
        let slip10_derive_child = SLIP10Derive::new_from_key(intermediate, chain1).store_output(k.clone());

        match sh.runtime_exec(slip10_derive_child.build()).await {
            Ok(data) => data.get(&k).cloned().unwrap(),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    };

    assert_eq!(cc0, cc1);
}

#[actix::test]
async fn usecase_ed25519_as_complex() {
    let (_cp, sh) = setup_stronghold().await;

    let msg = fresh::bytestring();
    let pk_result = DataKey::new("pub-key");
    let sign_result = DataKey::new("signed");

    let generate = Slip10Generate::new(fresh::coinflip().then(|| fresh::usize(1024)));
    let derive = SLIP10Derive::new_from_seed(generate.target_location(), fresh::hd_path().1);
    let get_pk = Ed25519PublicKey::new(derive.target_location()).store_output(pk_result.clone());
    let sign = Ed25519Sign::new(derive.target_location(), msg.clone()).store_output(sign_result.clone());

    let combined_proc = generate.then(derive).then(get_pk).then(sign).build();
    let mut output = sh.runtime_exec(combined_proc).await.unwrap();

    let pub_key_vec = output.remove(&pk_result).unwrap();
    let pk = PublicKey::try_from_bytes(pub_key_vec.try_into().unwrap()).unwrap();
    let sig_vec = output.remove(&sign_result).unwrap();
    let sig = Signature::from_bytes(sig_vec.try_into().unwrap());
    assert!(pk.verify(&sig, &msg));
}

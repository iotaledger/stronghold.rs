// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crypto::{
    hashes::sha::{SHA256, SHA256_LEN},
    keys::slip10,
    signatures::ed25519::{PublicKey, SecretKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    utils::rand::fill,
};

use super::fresh;
use crate::{
    procedures::{
        crypto::{ChainCode, Sha256},
        BIP39Generate, Ed25519PublicKey, Ed25519Sign, Hash, MnemonicLanguage, OutputInfo, OutputKey, ProcedureIo,
        ProcedureStep, Slip10Derive, Slip10Generate, TargetInfo, WriteVault,
    },
    Stronghold,
};

async fn setup_stronghold() -> (Vec<u8>, Stronghold) {
    let cp = fresh::bytestring(u8::MAX.into());

    let s = Stronghold::init_stronghold_system(cp.clone(), vec![]).await.unwrap();
    (cp, s)
}

#[actix::test]
async fn usecase_ed25519() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    if fresh::coinflip() {
        let _size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };
        let slip10_generate = Slip10Generate::default().write_secret(seed.clone(), fresh::record_hint());

        match sh.runtime_exec(slip10_generate).await.unwrap() {
            Ok(_) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    } else {
        let bip32_gen = BIP39Generate::new(MnemonicLanguage::English, fresh::passphrase())
            .write_secret(seed.clone(), fresh::record_hint());
        match sh.runtime_exec(bip32_gen).await.unwrap() {
            Ok(_) => (),
            Err(err) => panic!("unexpected error: {:?}", err),
        }
    }

    let (_path, chain) = fresh::hd_path();
    let key = fresh::location();

    let slip10_derive = Slip10Derive::new_from_seed(seed, chain).write_secret(key.clone(), fresh::record_hint());
    match sh.runtime_exec(slip10_derive).await.unwrap() {
        Ok(_) => (),
        Err(err) => panic!("unexpected error: {:?}", err),
    };

    let k = OutputKey::random();
    let ed25519_pk = Ed25519PublicKey::new(key.clone()).store_output(k.clone());
    let pk: [u8; PUBLIC_KEY_LENGTH] = match sh.runtime_exec(ed25519_pk).await.unwrap() {
        Ok(mut data) => data.take(&k).unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let msg = fresh::bytestring(4096);

    let k = OutputKey::random();
    let ed25519_sign = Ed25519Sign::new(msg.clone(), key).store_output(k.clone());
    let sig: [u8; SIGNATURE_LENGTH] = match sh.runtime_exec(ed25519_sign).await.unwrap() {
        Ok(mut data) => data.take(&k).unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let pk = PublicKey::try_from_bytes(pk).unwrap();
    let sig = Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));
}

#[actix::test]
async fn usecase_Slip10Derive_intermediate_keys() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    let slip10_generate = Slip10Generate::default().write_secret(seed.clone(), fresh::record_hint());
    match sh.runtime_exec(slip10_generate).await.unwrap() {
        Ok(_) => (),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0: ChainCode = {
        let k = OutputKey::random();
        let slip10_derive = Slip10Derive::new_from_seed(seed.clone(), chain0.join(&chain1)).store_output(k.clone());

        match sh.runtime_exec(slip10_derive).await.unwrap() {
            Ok(mut data) => data.take(&k).unwrap(),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    };

    let cc1: ChainCode = {
        let intermediate = fresh::location();

        let slip10_derive_intermediate =
            Slip10Derive::new_from_seed(seed, chain0).write_secret(intermediate.clone(), fresh::record_hint());

        match sh.runtime_exec(slip10_derive_intermediate).await.unwrap() {
            Ok(_) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        let k = OutputKey::random();
        let slip10_derive_child = Slip10Derive::new_from_key(intermediate, chain1).store_output(k.clone());

        match sh.runtime_exec(slip10_derive_child).await.unwrap() {
            Ok(mut data) => data.take(&k).unwrap(),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    };

    assert_eq!(cc0, cc1);
}

#[actix::test]
async fn usecase_ed25519_as_complex() {
    let (_cp, sh) = setup_stronghold().await;

    let msg = fresh::bytestring(4096);

    let pk_result = OutputKey::random();
    let sign_result = OutputKey::random();

    let generate = Slip10Generate::default();
    let derive = Slip10Derive::new_from_seed(generate.target(), fresh::hd_path().1);
    let get_pk = Ed25519PublicKey::new(derive.target()).store_output(pk_result.clone());
    let sign = Ed25519Sign::new(msg.clone(), derive.target()).store_output(sign_result.clone());

    let combined_proc = generate.then(derive).then(get_pk).then(sign);
    let mut output = match sh.runtime_exec(combined_proc).await.unwrap() {
        Ok(o) => o,
        Err(e) => panic!("Unexpected error: {}", e),
    };

    let pub_key_vec: [u8; PUBLIC_KEY_LENGTH] = output.take(&pk_result).unwrap();
    let pk = PublicKey::try_from_bytes(pub_key_vec).unwrap();
    let sig_vec: [u8; SIGNATURE_LENGTH] = output.take(&sign_result).unwrap();
    let sig = Signature::from_bytes(sig_vec);
    assert!(pk.verify(&sig, &msg));
}

#[actix::test]
async fn usecase_collection_of_data() {
    let (_cp, sh) = setup_stronghold().await;

    let key: Vec<u8> = {
        let size_bytes = fresh::coinflip().then(|| fresh::usize(1024)).unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed).unwrap();
        let dk = slip10::Seed::from_bytes(&seed)
            .derive(slip10::Curve::Ed25519, &fresh::hd_path().1)
            .unwrap();
        dk.into()
    };

    // write seed to vault
    let key_location = fresh::location();
    let write_vault_proc = WriteVault::new(key.clone(), key_location.clone(), fresh::record_hint());
    match sh.runtime_exec(write_vault_proc).await.unwrap() {
        Ok(data) => assert!(data.into_iter().next().is_none()),
        Err(e) => panic!("unexpected error: {:?}", e),
    }

    // test sign and hash

    let messages = vec![Vec::from("msg1"), Vec::from("msg2"), Vec::from("msg3")];

    let expected = messages
        .clone()
        .into_iter()
        .map(|msg| {
            // Sign message
            let mut raw = key.clone();
            raw.truncate(32);
            let mut bs = [0; 32];
            bs.copy_from_slice(&raw);
            let sk = SecretKey::from_bytes(bs);
            let sig = sk.sign(&msg).to_bytes();

            // SHA-256 hash the signed message
            let mut digest = [0; SHA256_LEN];
            SHA256(&sig, &mut digest);
            digest
        })
        .filter(|bytes| bytes.iter().any(|b| b <= &10u8))
        .fold(Vec::new(), |mut acc, curr| {
            acc.extend_from_slice(&curr);
            acc
        });

    // test procedure
    let proc = messages
        .into_iter()
        .enumerate()
        .map(|(i, msg)| {
            let sign = Ed25519Sign::new(msg, key_location.clone());
            let digest = Hash::<Sha256>::new(sign.output_key()).store_output(OutputKey::new(format!("{}", i)));
            sign.then(digest)
        })
        .reduce(|acc, curr| acc.then(curr))
        .unwrap();
    let mut output = match sh.runtime_exec(proc).await.unwrap() {
        Ok(o) => o.into_iter().collect::<Vec<(OutputKey, ProcedureIo)>>(),
        Err(e) => panic!("Unexpected error: {}", e),
    };
    output.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
    let res = output
        .into_iter()
        .map(|(_, v)| v)
        .filter(|bytes| bytes.iter().any(|b| b <= &10u8))
        .fold(Vec::new(), |mut acc, curr| {
            acc.extend_from_slice(&curr);
            acc
        });
    assert_eq!(res, expected);
}

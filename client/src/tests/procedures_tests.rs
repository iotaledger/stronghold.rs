// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crypto::{
    ciphers::{aes::Aes256Gcm, chacha::XChaCha20Poly1305, traits::Aead},
    hashes::sha::{SHA256, SHA256_LEN},
    keys::slip10,
    signatures::ed25519,
    utils::rand::fill,
};
use stronghold_utils::random;

use super::fresh;
use crate::{
    procedures::{
        crypto::{ChainCode, Sha256},
        AeadDecrypt, AeadEncrypt, BIP39Generate, Ed25519, Ed25519Sign, GenerateKey, Hash, MnemonicLanguage, OutputInfo,
        OutputKey, PrimitiveProcedure, ProcedureIo, ProcedureStep, PublicKey, Slip10Derive, Slip10Generate, TargetInfo,
        WriteVault, X25519DiffieHellman, X25519,
    },
    Location, Stronghold,
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

    let ed25519_pk = PublicKey::<Ed25519>::new(key.clone()).store_output(OutputKey::random());
    let pk: [u8; ed25519::PUBLIC_KEY_LENGTH] = match sh.runtime_exec(ed25519_pk).await.unwrap() {
        Ok(data) => data.single_output().unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let msg = fresh::bytestring(4096);

    let ed25519_sign = Ed25519Sign::new(msg.clone(), key).store_output(OutputKey::random());
    let sig: [u8; ed25519::SIGNATURE_LENGTH] = match sh.runtime_exec(ed25519_sign).await.unwrap() {
        Ok(data) => data.single_output().unwrap(),
        Err(e) => panic!("unexpected error: {:?}", e),
    };

    let pk = ed25519::PublicKey::try_from_bytes(pk).unwrap();
    let sig = ed25519::Signature::from_bytes(sig);
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
        let slip10_derive =
            Slip10Derive::new_from_seed(seed.clone(), chain0.join(&chain1)).store_output(OutputKey::random());

        match sh.runtime_exec(slip10_derive).await.unwrap() {
            Ok(data) => data.single_output().unwrap(),
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

        let slip10_derive_child = Slip10Derive::new_from_key(intermediate, chain1).store_output(OutputKey::random());

        match sh.runtime_exec(slip10_derive_child).await.unwrap() {
            Ok(data) => data.single_output().unwrap(),
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
    let get_pk = PublicKey::<Ed25519>::new(derive.target()).store_output(pk_result.clone());
    let sign = Ed25519Sign::new(msg.clone(), derive.target()).store_output(sign_result.clone());

    let combined_proc = generate.then(derive).then(get_pk).then(sign);
    let mut output = match sh.runtime_exec(combined_proc).await.unwrap() {
        Ok(o) => o,
        Err(e) => panic!("Unexpected error: {}", e),
    };

    let pub_key_vec: [u8; ed25519::PUBLIC_KEY_LENGTH] = output.take(&pk_result).unwrap();
    let pk = ed25519::PublicKey::try_from_bytes(pub_key_vec).unwrap();
    let sig_vec: [u8; ed25519::SIGNATURE_LENGTH] = output.take(&sign_result).unwrap();
    let sig = ed25519::Signature::from_bytes(sig_vec);
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
            let sk = ed25519::SecretKey::from_bytes(bs);
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

async fn test_aead<T>(sh: &mut Stronghold, key_location: Location, key: &[u8])
where
    T: Aead,
    PrimitiveProcedure: From<AeadEncrypt<T>> + From<AeadDecrypt<T>>,
{
    let test_plaintext = random::bytestring(4096);
    let test_associated_data = random::bytestring(4096);
    let test_nonce = vec![random::random(); T::NONCE_LENGTH];

    // test encryption
    let ctx_key = OutputKey::new("ctx");
    let tag_key = OutputKey::new("tag");
    let aead = AeadEncrypt::<T>::new(
        key_location.clone(),
        test_plaintext.clone(),
        test_associated_data.clone(),
        test_nonce.to_vec(),
    )
    .store_ciphertext(ctx_key.clone())
    .store_tag(tag_key.clone());

    let mut output = sh
        .runtime_exec(aead)
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("Unexpected error: {}", e));
    let out_ciphertext: Vec<u8> = output.take(&ctx_key).unwrap();
    let out_tag: Vec<u8> = output.take(&tag_key).unwrap();

    let mut expected_ctx = vec![0; test_plaintext.len()];
    let mut expected_tag = vec![0; T::TAG_LENGTH];
    T::try_encrypt(
        key,
        &test_nonce,
        &test_associated_data,
        &test_plaintext,
        &mut expected_ctx,
        &mut expected_tag,
    )
    .unwrap_or_else(|e| panic!("Unexpected error: {}", e));

    assert_eq!(expected_ctx, out_ciphertext);
    assert_eq!(expected_tag, out_tag);

    // test decryption
    let ptx_key = OutputKey::new("ptx");
    let adad = AeadDecrypt::<T>::new(
        key_location,
        out_ciphertext.clone(),
        test_associated_data.clone(),
        out_tag.clone(),
        test_nonce.to_vec(),
    )
    .store_plaintext(ptx_key.clone());

    let mut output = sh
        .runtime_exec(adad)
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("Unexpected error: {}", e));
    let out_plaintext: Vec<u8> = output.take(&ptx_key).unwrap();

    let mut expected_ptx = vec![0; out_ciphertext.len()];
    T::try_decrypt(
        key,
        &test_nonce,
        &test_associated_data,
        &mut expected_ptx,
        &out_ciphertext,
        &out_tag,
    )
    .unwrap_or_else(|e| panic!("Unexpected error: {}", e));

    assert_eq!(expected_ptx, out_plaintext);
    assert_eq!(out_plaintext, test_plaintext);
}

#[actix::test]
async fn usecase_aead() {
    let (_cp, mut sh) = setup_stronghold().await;

    // Init key
    let key_location = fresh::location();
    let key = ed25519::SecretKey::generate().unwrap().to_bytes();
    sh.write_to_vault(key_location.clone(), key.to_vec(), fresh::record_hint(), Vec::new())
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("Unexpected error: {}", e));

    test_aead::<Aes256Gcm>(&mut sh, key_location.clone(), &key).await;
    test_aead::<XChaCha20Poly1305>(&mut sh, key_location.clone(), &key).await;
}

#[actix::test]
async fn usecase_diffie_hellman() {
    let (cp, sh) = setup_stronghold().await;
    let sk1 = GenerateKey::<X25519>::default();
    let pk1 = PublicKey::<X25519>::new(sk1.target());
    let sk2 = GenerateKey::<X25519>::default();
    let pk2 = PublicKey::<X25519>::new(sk2.target());
    let key_1_2 = fresh::location();
    let dh_1_2 =
        X25519DiffieHellman::new(pk2.output_key(), sk1.target()).write_secret(key_1_2.clone(), fresh::record_hint());
    let key_2_1 = fresh::location();
    let dh_2_1 =
        X25519DiffieHellman::new(pk1.output_key(), sk2.target()).write_secret(key_2_1.clone(), fresh::record_hint());

    sh.runtime_exec(sk1.then(pk1).then(sk2).then(pk2).then(dh_1_2).then(dh_2_1))
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("Unexpected error: {}", e));

    let shared_1_2 = sh.read_secret(cp.clone(), key_1_2).await.unwrap().unwrap();
    let shared_2_1 = sh.read_secret(cp, key_2_1).await.unwrap().unwrap();

    assert_eq!(shared_1_2, shared_2_1)
}

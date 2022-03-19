// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crypto::{
    ciphers::{aes::Aes256Gcm, chacha::XChaCha20Poly1305, traits::Aead},
    keys::slip10,
    signatures::ed25519,
    utils::rand::fill,
};
use stronghold_utils::random::{self, bytestring};

use super::fresh;
use crate::{
    procedures::{
        AeadCipher, AeadDecrypt, AeadEncrypt, BIP39Generate, BIP39Recover, ChainCode, CopyRecord, DeriveSecret,
        Ed25519Sign, GenerateKey, GenerateSecret, Hkdf, KeyType, MnemonicLanguage, PublicKey, Sha2Hash, Slip10Derive,
        Slip10DeriveInput, Slip10Generate, X25519DiffieHellman,
    },
    Location, Stronghold,
};

async fn setup_stronghold() -> Result<(Vec<u8>, Stronghold), Box<dyn std::error::Error>> {
    let cp = fresh::bytestring(u8::MAX.into());

    let s = Stronghold::init_stronghold_system(cp.clone(), vec![]).await?;
    Ok((cp, s))
}

#[actix::test]
async fn usecase_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;

    let vault_path = bytestring(1024);
    let seed = Location::generic(vault_path.clone(), bytestring(1024));
    let seed_hint = fresh::record_hint();

    if fresh::coinflip() {
        let size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };
        let slip10_generate = Slip10Generate {
            size_bytes,
            output: seed.clone(),
            hint: seed_hint,
        };

        sh.runtime_exec(slip10_generate).await??
    } else {
        let bip32_gen = BIP39Generate {
            passphrase: fresh::passphrase(),
            output: seed.clone(),
            hint: seed_hint,
            language: MnemonicLanguage::English,
        };
        sh.runtime_exec(bip32_gen).await??;
    }

    let (_path, chain) = fresh::hd_path();
    let key = Location::generic(vault_path.clone(), bytestring(1024));
    let key_hint = fresh::record_hint();

    let slip10_derive = Slip10Derive {
        chain,
        input: Slip10DeriveInput::Seed(seed.clone()),
        output: key.clone(),
        hint: key_hint,
    };
    sh.runtime_exec(slip10_derive).await??;

    let ed25519_pk = PublicKey {
        private_key: key.clone(),
        ty: KeyType::Ed25519,
    };
    let pk: [u8; ed25519::PUBLIC_KEY_LENGTH] = sh.runtime_exec(ed25519_pk).await??;

    let msg = fresh::bytestring(4096);

    let ed25519_sign = Ed25519Sign {
        private_key: key.clone(),
        msg: msg.clone(),
    };
    let sig: [u8; ed25519::SIGNATURE_LENGTH] = sh.runtime_exec(ed25519_sign).await??;

    let pk = ed25519::PublicKey::try_from_bytes(pk)?;
    let sig = ed25519::Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));

    let list = sh.list_hints_and_ids(vault_path).await?;
    assert_eq!(list.len(), 2);
    let (_, hint) = list.iter().find(|(id, _)| *id == seed.resolve().1).unwrap();
    assert_eq!(*hint, seed_hint);
    let (_, hint) = list.iter().find(|(id, _)| *id == key.resolve().1).unwrap();
    assert_eq!(*hint, key_hint);
    Ok(())
}

#[actix::test]
async fn usecase_Slip10Derive_intermediate_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;

    let seed = fresh::location();

    let slip10_generate = Slip10Generate {
        output: seed.clone(),
        hint: fresh::record_hint(),
        size_bytes: None,
    };
    sh.runtime_exec(slip10_generate).await??;

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0: ChainCode = {
        let slip10_derive = Slip10Derive {
            input: Slip10DeriveInput::Seed(seed.clone()),
            chain: chain0.join(&chain1),
            output: fresh::location(),
            hint: fresh::record_hint(),
        };

        sh.runtime_exec(slip10_derive).await??
    };

    let cc1: ChainCode = {
        let intermediate = fresh::location();

        let slip10_derive_intermediate = Slip10Derive {
            input: Slip10DeriveInput::Seed(seed.clone()),
            chain: chain0,
            output: intermediate.clone(),
            hint: fresh::record_hint(),
        };

        sh.runtime_exec(slip10_derive_intermediate).await??;

        let slip10_derive_child = Slip10Derive {
            input: Slip10DeriveInput::Key(intermediate),
            chain: chain1,
            output: fresh::location(),
            hint: fresh::record_hint(),
        };

        sh.runtime_exec(slip10_derive_child).await??
    };

    assert_eq!(cc0, cc1);
    Ok(())
}

#[actix::test]
async fn usecase_ed25519_as_complex() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;

    let msg = fresh::bytestring(4096);

    let generate = Slip10Generate {
        size_bytes: None,
        output: fresh::location(),
        hint: fresh::record_hint(),
    };
    let derive = Slip10Derive {
        input: Slip10DeriveInput::Seed(generate.target().0.clone()),
        output: fresh::location(),
        chain: fresh::hd_path().1,
        hint: fresh::record_hint(),
    };
    let get_pk = PublicKey {
        ty: KeyType::Ed25519,
        private_key: derive.target().0.clone(),
    };
    let sign = Ed25519Sign {
        msg: msg.clone(),
        private_key: derive.target().0.clone(),
    };

    let procedures = vec![generate.into(), derive.into(), get_pk.into(), sign.into()];
    let mut output = sh.runtime_exec_chained(procedures).await??.into_iter();

    // Skip output from Slip10Generate and Slip10Derive;
    output.next();
    output.next();

    let pub_key_vec: [u8; ed25519::PUBLIC_KEY_LENGTH] = output.next().unwrap().try_into().unwrap();
    let pk = ed25519::PublicKey::try_from_bytes(pub_key_vec)?;
    let sig_vec: [u8; ed25519::SIGNATURE_LENGTH] = output.next().unwrap().try_into().unwrap();
    let sig = ed25519::Signature::from_bytes(sig_vec);
    assert!(pk.verify(&sig, &msg));
    Ok(())
}

#[actix::test]
async fn usecase_collection_of_data() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;

    let key: Vec<u8> = {
        let size_bytes = fresh::coinflip().then(|| fresh::usize(1024)).unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        let dk = slip10::Seed::from_bytes(&seed).derive(slip10::Curve::Ed25519, &fresh::hd_path().1)?;
        dk.into()
    };

    // write seed to vault
    let key_location = fresh::location();
    sh.write_to_vault(key_location.clone(), key.clone(), fresh::record_hint(), Vec::new())
        .await??;

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
            sk.sign(&msg).to_bytes()
        })
        .filter(|bytes| bytes.iter().any(|b| b <= &10u8))
        .fold(Vec::new(), |mut acc, curr| {
            acc.extend_from_slice(&curr);
            acc
        });

    // test procedure
    let procedures = messages
        .into_iter()
        .map(|msg| {
            Ed25519Sign {
                msg,
                private_key: key_location.clone(),
            }
            .into()
        })
        .collect();
    let output = sh.runtime_exec_chained(procedures).await??;
    let res = output
        .into_iter()
        .map(|v| v.into())
        .filter(|bytes: &Vec<u8>| bytes.iter().any(|b| b <= &10u8))
        .fold(Vec::new(), |mut acc, curr| {
            acc.extend_from_slice(&curr);
            acc
        });
    assert_eq!(res, expected);
    Ok(())
}

async fn test_aead(
    sh: &mut Stronghold,
    key_location: Location,
    key: &[u8],
    cipher: AeadCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_plaintext = random::bytestring(4096);
    let test_associated_data = random::bytestring(4096);
    let nonce_len = match cipher {
        AeadCipher::Aes256Gcm => Aes256Gcm::NONCE_LENGTH,
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::NONCE_LENGTH,
    };
    let mut test_nonce = Vec::with_capacity(nonce_len);
    for _ in 0..test_nonce.capacity() {
        test_nonce.push(random::random())
    }

    // test encryption
    let aead = AeadEncrypt {
        cipher,
        key: key_location.clone(),
        plaintext: test_plaintext.clone(),
        associated_data: test_associated_data.clone(),
        nonce: test_nonce.clone(),
    };

    let tag_len = match cipher {
        AeadCipher::Aes256Gcm => Aes256Gcm::TAG_LENGTH,
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::TAG_LENGTH,
    };
    let mut output = sh.runtime_exec(aead).await??;
    let out_tag: Vec<u8> = output.drain(..tag_len).collect();
    let out_ciphertext = output;

    let mut expected_ctx = vec![0; test_plaintext.len()];
    let mut expected_tag = vec![0; tag_len];

    let f = match cipher {
        AeadCipher::Aes256Gcm => Aes256Gcm::try_encrypt,
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_encrypt,
    };
    f(
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
    let adad = AeadDecrypt {
        cipher,
        key: key_location,
        ciphertext: out_ciphertext.clone(),
        associated_data: test_associated_data.clone(),
        tag: out_tag.clone(),
        nonce: test_nonce.to_vec(),
    };

    let out_plaintext = sh.runtime_exec(adad).await??;

    let mut expected_ptx = vec![0; out_ciphertext.len()];

    let f = match cipher {
        AeadCipher::Aes256Gcm => Aes256Gcm::try_decrypt,
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_decrypt,
    };
    f(
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

    Ok(())
}

#[actix::test]
async fn usecase_aead() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, mut sh) = setup_stronghold().await?;

    // Init key
    let key_location = fresh::location();
    let key = ed25519::SecretKey::generate()?.to_bytes();
    sh.write_to_vault(key_location.clone(), key.to_vec(), fresh::record_hint(), Vec::new())
        .await??;

    test_aead(&mut sh, key_location.clone(), &key, AeadCipher::Aes256Gcm).await?;
    test_aead(&mut sh, key_location.clone(), &key, AeadCipher::XChaCha20Poly1305).await?;
    Ok(())
}

#[actix::test]
async fn usecase_diffie_hellman() -> Result<(), Box<dyn std::error::Error>> {
    let (cp, sh) = setup_stronghold().await?;

    let sk1_location = fresh::location();
    let sk1 = GenerateKey {
        ty: KeyType::X25519,
        output: sk1_location.clone(),
        hint: fresh::record_hint(),
    };
    let pk1 = PublicKey {
        ty: KeyType::X25519,
        private_key: sk1.target().0.clone(),
    };
    let pub_key_1: [u8; 32] = sh
        .runtime_exec_chained(vec![sk1.into(), pk1.into()])
        .await??
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let sk2_location = fresh::location();
    let sk2 = GenerateKey {
        ty: KeyType::X25519,
        output: sk2_location.clone(),
        hint: fresh::record_hint(),
    };
    let pk2 = PublicKey {
        ty: KeyType::X25519,
        private_key: sk2.target().0.clone(),
    };
    let pub_key_2: [u8; 32] = sh
        .runtime_exec_chained(vec![sk2.into(), pk2.into()])
        .await??
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let mut salt = vec![];
    salt.extend_from_slice(&pub_key_1);
    salt.extend_from_slice(&pub_key_2);
    let label = bytestring(1024);

    let key_1_2 = fresh::location();
    let dh_1_2 = X25519DiffieHellman {
        private_key: sk1_location,
        public_key: pub_key_2,
        shared_key: fresh::location(),
        hint: fresh::record_hint(),
    };
    let derived_1_2 = Hkdf {
        hash_type: Sha2Hash::Sha256,
        salt: salt.clone(),
        label: label.clone(),
        ikm: dh_1_2.target().0.clone(),
        okm: key_1_2.clone(),
        hint: fresh::record_hint(),
    };

    let key_2_1 = fresh::location();
    let dh_2_1 = X25519DiffieHellman {
        private_key: sk2_location,
        public_key: pub_key_1,
        shared_key: fresh::location(),
        hint: fresh::record_hint(),
    };
    let derived_2_1 = Hkdf {
        hash_type: Sha2Hash::Sha256,
        salt: salt.clone(),
        label: label.clone(),
        ikm: dh_2_1.target().0.clone(),
        okm: key_2_1.clone(),
        hint: fresh::record_hint(),
    };

    let procedures = vec![dh_1_2.into(), derived_1_2.into(), dh_2_1.into(), derived_2_1.into()];

    sh.runtime_exec_chained(procedures).await??;

    let hashed_shared_1_2 = sh.read_secret(cp.clone(), key_1_2).await?.unwrap();
    let hashed_shared_2_1 = sh.read_secret(cp, key_2_1).await?.unwrap();

    assert_eq!(hashed_shared_1_2, hashed_shared_2_1);
    Ok(())
}

#[actix::test]
async fn usecase_recover_bip39() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;

    let passphrase = random::string(4096);
    let (_path, chain) = fresh::hd_path();
    let message = bytestring(4095);

    let generate_bip39 = BIP39Generate {
        language: MnemonicLanguage::English,
        passphrase: Some(passphrase.clone()),
        output: fresh::location(),
        hint: fresh::record_hint(),
    };
    let derive_from_original = Slip10Derive {
        input: Slip10DeriveInput::Seed(generate_bip39.target().0.clone()),
        chain: chain.clone(),
        output: fresh::location(),
        hint: fresh::record_hint(),
    };
    let sign_from_original = Ed25519Sign {
        msg: message.clone(),
        private_key: derive_from_original.target().0.clone(),
    };

    let procedures = vec![
        generate_bip39.into(),
        derive_from_original.into(),
        sign_from_original.into(),
    ];
    let mut output = sh.runtime_exec_chained(procedures).await??.into_iter();
    let mnemonic = output.next().unwrap().try_into()?;
    output.next().unwrap();
    let signed_with_original = output.next();

    let recover_bip39 = BIP39Recover {
        mnemonic,
        passphrase: Some(passphrase),
        output: fresh::location(),
        hint: fresh::record_hint(),
    };

    let derive_from_recovered = Slip10Derive {
        input: Slip10DeriveInput::Seed(recover_bip39.target().0.clone()),
        chain: chain.clone(),
        output: fresh::location(),
        hint: fresh::record_hint(),
    };
    let sign_from_recovered = Ed25519Sign {
        msg: message.clone(),
        private_key: derive_from_recovered.target().0.clone(),
    };

    let procedures = vec![
        recover_bip39.into(),
        derive_from_recovered.into(),
        sign_from_recovered.into(),
    ];
    let mut output = sh.runtime_exec_chained(procedures).await??.into_iter();
    output.next().unwrap();
    output.next().unwrap();
    let signed_with_recovered = output.next();

    assert_eq!(signed_with_original, signed_with_recovered);
    Ok(())
}

#[actix::test]
async fn usecase_move_record() -> Result<(), Box<dyn std::error::Error>> {
    let (_cp, sh) = setup_stronghold().await?;
    let test_msg = random::bytestring(4096);

    let first_location = fresh::location();
    let generate_key = GenerateKey {
        ty: KeyType::Ed25519,
        output: first_location.clone(),
        hint: fresh::record_hint(),
    };
    let pub_key = PublicKey {
        ty: KeyType::Ed25519,
        private_key: generate_key.target().0.clone(),
    };
    let sign_message = Ed25519Sign {
        msg: test_msg.clone(),
        private_key: generate_key.target().0.clone(),
    };
    let procedures = vec![generate_key.into(), pub_key.into(), sign_message.into()];
    let mut output = sh.runtime_exec_chained(procedures).await??.into_iter();

    output.next().unwrap();

    let public_key = output.next().unwrap();
    let mut first: Vec<u8> = public_key.into();
    let second: Vec<u8> = first.drain(first.len() % 2..).collect();

    // signed message used for validation further in the test
    let signed_with_original: Vec<u8> = output.next().unwrap().into();

    // pub-key used to derive the new location for the private key

    // Copy record to new location derived from the pub-key
    let new_location = Location::generic(first, second);
    let copy_record = CopyRecord {
        source: first_location.clone(),
        target: new_location.clone(),
        hint: fresh::record_hint(),
    };
    sh.runtime_exec(copy_record).await??;

    // Remove record from old location
    sh.delete_data(first_location, true).await??;

    // Validate by signing the message from the new location
    let sign_message = Ed25519Sign {
        msg: test_msg.clone(),
        private_key: new_location,
    };
    let signed_with_moved: Vec<u8> = sh.runtime_exec(sign_message).await??.into();
    assert_eq!(signed_with_original, signed_with_moved);

    Ok(())
}

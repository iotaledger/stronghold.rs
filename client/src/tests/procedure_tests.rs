// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::ciphers::aes_kw::AesKeyWrap;

#[cfg(feature = "insecure")]
use crate::procedures::CompareSecret;

use crate::{
    procedures::{
        AeadCipher, AeadDecrypt, AeadEncrypt, AesKeyWrapCipher, AesKeyWrapDecrypt, AesKeyWrapEncrypt, BIP39Generate,
        BIP39Recover, ConcatKdf, CopyRecord, DeriveSecret, Ed25519Sign, Secp256k1EcdsaSign, GenerateKey, GenerateSecret, Hkdf, KeyType,
        MnemonicLanguage, PublicKey, GetEvmAddress, Sha2Hash, Slip10Derive, Slip10DeriveInput, Slip10Generate, StrongholdProcedure,
        WriteVault, X25519DiffieHellman,
    },
    tests::fresh,
    Client, Location, Stronghold,
};

use crypto::{
    ciphers::{aes_gcm::Aes256Gcm, chacha::XChaCha20Poly1305},
    keys::slip10,
    signatures::{ed25519, secp256k1_ecdsa},
};
use stronghold_utils::random;

#[test]
fn usecase_diffie_hellman_concat_kdf() {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let sk1_location: Location = fresh::location();
    let sk1: GenerateKey = GenerateKey {
        ty: KeyType::X25519,
        output: sk1_location.clone(),
    };

    let pk1: PublicKey = PublicKey {
        ty: KeyType::X25519,
        private_key: sk1.target().clone(),
    };

    let pub_key_1: [u8; 32] = client
        .execute_procedure_chained(vec![sk1.into(), pk1.into()])
        .unwrap()
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let sk2_location: Location = fresh::location();
    let sk2: GenerateKey = GenerateKey {
        ty: KeyType::X25519,
        output: sk2_location.clone(),
    };
    let pk2: PublicKey = PublicKey {
        ty: KeyType::X25519,
        private_key: sk2.target().clone(),
    };
    let pub_key_2: [u8; 32] = client
        .execute_procedure_chained(vec![sk2.into(), pk2.into()])
        .unwrap()
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let key_1_2: Location = fresh::location();
    let dh_1_2: X25519DiffieHellman = X25519DiffieHellman {
        private_key: sk1_location,
        public_key: pub_key_2,
        shared_key: fresh::location(),
    };
    let derived_1_2: ConcatKdf = ConcatKdf {
        hash: Sha2Hash::Sha256,
        algorithm_id: "ECDH".to_owned(),
        shared_secret: dh_1_2.target().clone(),
        key_len: 32,
        apu: vec![],
        apv: vec![],
        output: key_1_2.clone(),
        pub_info: vec![],
        priv_info: vec![],
    };

    let key_2_1: Location = fresh::location();
    let dh_2_1: X25519DiffieHellman = X25519DiffieHellman {
        private_key: sk2_location,
        public_key: pub_key_1,
        shared_key: fresh::location(),
    };
    let derived_2_1: ConcatKdf = ConcatKdf {
        hash: Sha2Hash::Sha256,
        algorithm_id: "ECDH".to_owned(),
        shared_secret: dh_2_1.target().clone(),
        key_len: 32,
        apu: vec![],
        apv: vec![],
        output: key_2_1.clone(),
        pub_info: vec![],
        priv_info: vec![],
    };

    let procedures: Vec<StrongholdProcedure> =
        vec![dh_1_2.into(), derived_1_2.into(), dh_2_1.into(), derived_2_1.into()];

    client.execute_procedure_chained(procedures).unwrap();

    let derived_shared_secret_1_2 = client
        .vault(key_1_2.vault_path())
        .read_secret(key_1_2.record_path())
        .unwrap();
    let derived_shared_secret_2_1 = client
        .vault(key_2_1.vault_path())
        .read_secret(key_2_1.record_path())
        .unwrap();

    assert_eq!(derived_shared_secret_1_2, derived_shared_secret_2_1);
}

// Test vector from https://www.rfc-editor.org/rfc/rfc7518.html#appendix-C
// This uses the concat KDF in the context of JWA.
#[test]
fn test_concat_kdf_with_jwa() {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let secret_location: Location = fresh::location();
    let concat_output: Location = fresh::location();
    let write = WriteVault {
        data: vec![
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128,
            106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ],
        location: secret_location,
    };

    let key_len: usize = 16;

    let kdf: ConcatKdf = ConcatKdf {
        hash: Sha2Hash::Sha256,
        algorithm_id: "A128GCM".to_owned(),
        shared_secret: write.target().clone(),
        key_len,
        apu: b"Alice".to_vec(),
        apv: b"Bob".to_vec(),
        output: concat_output.clone(),
        pub_info: ((key_len * 8) as u32).to_be_bytes().to_vec(),
        priv_info: vec![],
    };

    client
        .execute_procedure_chained(vec![write.into(), kdf.into()])
        .unwrap();

    let derived_key_material = client
        .vault(concat_output.vault_path())
        .read_secret(concat_output.record_path())
        .unwrap();

    assert_eq!(
        derived_key_material,
        vec![86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
    );
}

#[test]
fn test_aes_256_keywrap_roundtrip() {
    // Test Vector from https://tools.ietf.org/html/rfc3394#section-4.6.
    let encryption_key: Vec<u8> = vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31,
    ];
    let plaintext: Vec<u8> = vec![
        0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15,
    ];
    let ciphertext: Vec<u8> = vec![
        40, 201, 244, 4, 196, 184, 16, 244, 203, 204, 179, 92, 251, 135, 248, 38, 63, 87, 134, 226, 216, 14, 211, 38,
        203, 199, 240, 231, 26, 153, 244, 59, 251, 152, 139, 155, 122, 2, 221, 33,
    ];

    let client: Client = Client::default();

    let encryption_key_location: Location = fresh::location();
    let wrap_key_location: Location = fresh::location();
    let plaintext_location: Location = fresh::location();

    client
        .execute_procedure(WriteVault {
            data: encryption_key,
            location: encryption_key_location.clone(),
        })
        .unwrap();

    client
        .execute_procedure(WriteVault {
            data: plaintext.clone(),
            location: wrap_key_location.clone(),
        })
        .unwrap();

    let ctx: Vec<u8> = client
        .execute_procedure(AesKeyWrapEncrypt {
            cipher: AesKeyWrapCipher::Aes256,
            encryption_key: encryption_key_location.clone(),
            wrap_key: wrap_key_location,
        })
        .unwrap();

    assert_eq!(ctx, ciphertext);

    client
        .execute_procedure(AesKeyWrapDecrypt {
            cipher: AesKeyWrapCipher::Aes256,
            decryption_key: encryption_key_location,
            wrapped_key: ciphertext,
            output: plaintext_location.clone(),
        })
        .unwrap();

    let ptx: Vec<u8> = client
        .vault(plaintext_location.vault_path())
        .read_secret(plaintext_location.record_path())
        .unwrap();

    assert_eq!(ptx, plaintext);
}

#[tokio::test]
async fn usecase_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let vault_path = random::variable_bytestring(1024);
    let seed = Location::generic(vault_path.clone(), random::variable_bytestring(1024));

    if fresh::coinflip() {
        let size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };
        let slip10_generate = Slip10Generate {
            size_bytes,
            output: seed.clone(),
        };

        assert!(client.execute_procedure(slip10_generate).is_ok());
    } else {
        let bip32_gen = BIP39Generate {
            passphrase: random::passphrase(),
            output: seed.clone(),
            language: MnemonicLanguage::English,
        };
        assert!(client.execute_procedure(bip32_gen).is_ok());
    }

    let (_path, chain) = fresh::hd_path();
    let key = Location::generic(vault_path, random::variable_bytestring(1024));

    let slip10_derive = Slip10Derive {
        curve: slip10::Curve::Ed25519,
        chain,
        input: Slip10DeriveInput::Seed(seed),
        output: key.clone(),
    };
    assert!(client.execute_procedure(slip10_derive).is_ok());

    let ed25519_pk = PublicKey {
        private_key: key.clone(),
        ty: KeyType::Ed25519,
    };
    let pk = client.execute_procedure(ed25519_pk).unwrap();

    let msg = fresh::variable_bytestring(4096);

    let ed25519_sign = Ed25519Sign {
        private_key: key,
        msg: msg.clone(),
    };
    let sig: [u8; ed25519::SIGNATURE_LENGTH] = client.execute_procedure(ed25519_sign).unwrap();

    let pk = ed25519::PublicKey::try_from_bytes(pk[..].try_into().unwrap()).unwrap();
    let sig = ed25519::Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));

    Ok(())
}

#[tokio::test]
async fn usecase_secp256k1() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let vault_path = random::variable_bytestring(1024);
    let sk = Location::generic(vault_path.clone(), random::variable_bytestring(1024));
    let seed = Location::generic(vault_path.clone(), random::variable_bytestring(1024));
    let esk = Location::generic(vault_path, random::variable_bytestring(1024));

    let slip10_generate = Slip10Generate {
        size_bytes: Some(17),
        output: seed.clone(),
    };
    assert!(client.execute_procedure(slip10_generate).is_ok());

    let chain = slip10::Chain::from_u32([0x80000000_u32, 1, 2, 0x80000003_u32]);
    let slip10_derive = Slip10Derive {
        curve: slip10::Curve::Secp256k1,
        chain,
        input: Slip10DeriveInput::Seed(seed),
        output: esk.clone(),
    };
    assert!(client.execute_procedure(slip10_derive).is_ok());

    let secp256k1_ecdsa_generate = GenerateKey {
        ty: KeyType::Secp256k1Ecdsa,
        output: sk.clone(),
    };
    assert!(client.execute_procedure(secp256k1_ecdsa_generate).is_ok());

    let run = |sk: Location| {
        let secp256k1_ecdsa_public_key = PublicKey {
            private_key: sk.clone(),
            ty: KeyType::Secp256k1Ecdsa,
        };
        let pk_vec = client.execute_procedure(secp256k1_ecdsa_public_key).unwrap();
        let pk = secp256k1_ecdsa::PublicKey::try_from_slice(&pk_vec).unwrap();

        let evm_address = GetEvmAddress {
            private_key: sk.clone(),
        };
        let evm_addr = client.execute_procedure(evm_address).unwrap();

        assert_eq!(&evm_addr, pk.to_address().as_ref());

        let msg = fresh::variable_bytestring(4096);

        let secp256k1_ecdsa_sign = Secp256k1EcdsaSign {
            private_key: sk.clone(),
            msg: msg.clone(),
        };
        let mut sig_bytes: [u8; secp256k1_ecdsa::SIGNATURE_LENGTH] = client.execute_procedure(secp256k1_ecdsa_sign).unwrap();

        let sig = secp256k1_ecdsa::Signature::try_from_bytes(&sig_bytes).unwrap();
        assert!(pk.verify(&sig, &msg));
        assert_eq!(pk, sig.verify_recover(&msg).unwrap());

        sig_bytes[0] ^= 1;
        let sig_bad = secp256k1_ecdsa::Signature::try_from_bytes(&sig_bytes).unwrap();
        assert!(!pk.verify(&sig_bad, &msg));
    };

    run(sk);
    run(esk);

    Ok(())
}

#[tokio::test]
async fn usecase_slip10derive_intermediate_keys() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let seed = fresh::location();

    let slip10_generate = Slip10Generate {
        output: seed.clone(),
        size_bytes: None,
    };
    assert!(client.execute_procedure(slip10_generate).is_ok());

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0: slip10::ChainCode = {
        let slip10_derive = Slip10Derive {
            curve: slip10::Curve::Ed25519,
            input: Slip10DeriveInput::Seed(seed.clone()),
            chain: chain0.join(&chain1),
            output: fresh::location(),
        };

        client.execute_procedure(slip10_derive).unwrap()
    };

    let cc1: slip10::ChainCode = {
        let intermediate = fresh::location();

        let slip10_derive_intermediate = Slip10Derive {
            curve: slip10::Curve::Ed25519,
            input: Slip10DeriveInput::Seed(seed),
            chain: chain0,
            output: intermediate.clone(),
        };

        assert!(client.execute_procedure(slip10_derive_intermediate).is_ok());

        let slip10_derive_child = Slip10Derive {
            curve: slip10::Curve::Ed25519,
            input: Slip10DeriveInput::Key(intermediate),
            chain: chain1,
            output: fresh::location(),
        };

        client.execute_procedure(slip10_derive_child).unwrap()
    };

    assert_eq!(cc0, cc1);
    Ok(())
}

#[tokio::test]
async fn usecase_ed25519_as_complex() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let msg = fresh::variable_bytestring(4096);

    let generate = Slip10Generate {
        size_bytes: None,
        output: fresh::location(),
    };
    let derive = Slip10Derive {
        curve: slip10::Curve::Ed25519,
        input: Slip10DeriveInput::Seed(generate.target().clone()),
        output: fresh::location(),
        chain: fresh::hd_path().1,
    };
    let get_pk = PublicKey {
        ty: KeyType::Ed25519,
        private_key: derive.target().clone(),
    };
    let sign = Ed25519Sign {
        msg: msg.clone(),
        private_key: derive.target().clone(),
    };

    let procedures = vec![generate.into(), derive.into(), get_pk.into(), sign.into()];
    let output = client.execute_procedure_chained(procedures).unwrap();

    let mut pub_key_vec: [u8; ed25519::PUBLIC_KEY_LENGTH] = [0u8; ed25519::PUBLIC_KEY_LENGTH];
    let proc_output: Vec<u8> = output[2].clone().into();
    pub_key_vec.clone_from_slice(proc_output.as_slice());

    let pk = ed25519::PublicKey::try_from_bytes(pub_key_vec).unwrap();

    let mut sig_vec: [u8; ed25519::SIGNATURE_LENGTH] = [0u8; ed25519::SIGNATURE_LENGTH];
    let sig_output: Vec<u8> = output[3].clone().into();
    sig_vec.clone_from_slice(sig_output.as_slice());

    let sig = ed25519::Signature::from_bytes(sig_vec);
    assert!(pk.verify(&sig, &msg));
    Ok(())
}

#[tokio::test]
async fn usecase_collection_of_data() -> Result<(), Box<dyn std::error::Error>> {
    use crypto::{keys::slip10, utils::rand::fill};

    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let key: Vec<u8> = {
        let size_bytes = fresh::coinflip().then(|| fresh::usize(1024)).unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];

        assert!(fill(&mut seed).is_ok(), "Failed to fill seed with random data");

        let dk = slip10::Seed::from_bytes(&seed)
            .derive(slip10::Curve::Ed25519, &fresh::hd_path().1)
            .unwrap();
        (*dk.extended_bytes()).into()
    };

    // write seed to vault
    let key_location = fresh::location();
    let vault_location = key_location.vault_path();

    let vault = client.vault(vault_location);

    assert!(vault.write_secret(key_location.clone(), key.clone()).is_ok());

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
    let output = client.execute_procedure_chained(procedures).unwrap();
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
    client: &Client,
    key_location: Location,
    key: &[u8],
    cipher: AeadCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    use crypto::ciphers::traits::*;

    let test_plaintext = random::variable_bytestring(4096);
    let test_associated_data = random::variable_bytestring(4096);
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
    let mut output = client.execute_procedure(aead).unwrap();
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

    let out_plaintext = client.execute_procedure(adad);

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

    assert_eq!(expected_ptx, out_plaintext.clone().unwrap());
    assert_eq!(out_plaintext.unwrap(), test_plaintext);

    Ok(())
}

#[tokio::test]
async fn usecase_aead() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    // Init key
    let key_location = fresh::location();
    let key = ed25519::SecretKey::generate().unwrap().to_bytes();

    let vault_path = key_location.vault_path();

    let vault = client.vault(vault_path);
    assert!(vault.write_secret(key_location.clone(), key.to_vec()).is_ok());

    test_aead(&client, key_location.clone(), &key, AeadCipher::Aes256Gcm).await?;
    test_aead(&client, key_location.clone(), &key, AeadCipher::XChaCha20Poly1305).await?;
    Ok(())
}

#[tokio::test]
async fn usecase_diffie_hellman() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let sk1_location = fresh::location();
    let sk1 = GenerateKey {
        ty: KeyType::X25519,
        output: sk1_location.clone(),
    };
    let pk1 = PublicKey {
        ty: KeyType::X25519,
        private_key: sk1.target().clone(),
    };
    let pub_key_1: [u8; 32] = client
        .execute_procedure_chained(vec![sk1.into(), pk1.into()])
        .unwrap()
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let sk2_location = fresh::location();
    let sk2 = GenerateKey {
        ty: KeyType::X25519,
        output: sk2_location.clone(),
    };
    let pk2 = PublicKey {
        ty: KeyType::X25519,
        private_key: sk2.target().clone(),
    };
    let pub_key_2: [u8; 32] = client
        .execute_procedure_chained(vec![sk2.into(), pk2.into()])
        .unwrap()
        .pop()
        .unwrap()
        .try_into()
        .unwrap();

    let mut salt = vec![];
    salt.extend_from_slice(&pub_key_1);
    salt.extend_from_slice(&pub_key_2);
    let label = random::variable_bytestring(1024);

    let key_1_2 = fresh::location();
    let dh_1_2 = X25519DiffieHellman {
        private_key: sk1_location,
        public_key: pub_key_2,
        shared_key: fresh::location(),
    };
    let derived_1_2 = Hkdf {
        hash_type: Sha2Hash::Sha256,
        salt: salt.clone(),
        label: label.clone(),
        ikm: dh_1_2.target().clone(),
        okm: key_1_2.clone(),
    };

    let key_2_1 = fresh::location();
    let dh_2_1 = X25519DiffieHellman {
        private_key: sk2_location,
        public_key: pub_key_1,
        shared_key: fresh::location(),
    };
    let derived_2_1 = Hkdf {
        hash_type: Sha2Hash::Sha256,
        salt: salt.clone(),
        label,
        ikm: dh_2_1.target().clone(),
        okm: key_2_1.clone(),
    };

    let procedures = vec![dh_1_2.into(), derived_1_2.into(), dh_2_1.into(), derived_2_1.into()];

    assert!(client.execute_procedure_chained(procedures).is_ok());

    let hashed_shared_1_2 = client
        .vault(key_1_2.vault_path())
        .read_secret(key_1_2.record_path())
        .unwrap();
    let hashed_shared_2_1 = client
        .vault(key_2_1.vault_path())
        .read_secret(key_2_1.record_path())
        .unwrap();

    assert_eq!(hashed_shared_1_2, hashed_shared_2_1);
    Ok(())
}

#[tokio::test]
async fn usecase_recover_bip39() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let passphrase = random::string(4096);
    let (_path, chain) = fresh::hd_path();
    let message = random::variable_bytestring(4095);

    let generate_bip39 = BIP39Generate {
        language: MnemonicLanguage::English,
        passphrase: Some(passphrase.clone()),
        output: fresh::location(),
    };
    let derive_from_original = Slip10Derive {
        curve: slip10::Curve::Ed25519,
        input: Slip10DeriveInput::Seed(generate_bip39.target().clone()),
        chain: chain.clone(),
        output: fresh::location(),
    };
    let sign_from_original = Ed25519Sign {
        msg: message.clone(),
        private_key: derive_from_original.target().clone(),
    };

    let procedures = vec![
        generate_bip39.into(),
        derive_from_original.into(),
        sign_from_original.into(),
    ];
    let output = client.execute_procedure_chained(procedures).unwrap();

    let mnemonic = output[0].clone().try_into().unwrap(); // ?
    let signed_with_original = output[2].clone();

    let recover_bip39 = BIP39Recover {
        mnemonic,
        passphrase: Some(passphrase),
        output: fresh::location(),
    };

    let derive_from_recovered = Slip10Derive {
        curve: slip10::Curve::Ed25519,
        input: Slip10DeriveInput::Seed(recover_bip39.target().clone()),
        chain,
        output: fresh::location(),
    };
    let sign_from_recovered = Ed25519Sign {
        msg: message,
        private_key: derive_from_recovered.target().clone(),
    };

    let procedures = vec![
        recover_bip39.into(),
        derive_from_recovered.into(),
        sign_from_recovered.into(),
    ];
    let output = client.execute_procedure_chained(procedures).unwrap();
    let signed_with_recovered = output[2].clone();

    assert_eq!(signed_with_original, signed_with_recovered);
    Ok(())
}

#[tokio::test]
async fn usecase_move_record() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let test_msg = random::variable_bytestring(4096);

    let first_location = fresh::location();
    let generate_key = GenerateKey {
        ty: KeyType::Ed25519,
        output: first_location.clone(),
    };
    let pub_key = PublicKey {
        ty: KeyType::Ed25519,
        private_key: generate_key.target().clone(),
    };
    let sign_message = Ed25519Sign {
        msg: test_msg.clone(),
        private_key: generate_key.target().clone(),
    };
    let procedures = vec![generate_key.into(), pub_key.into(), sign_message.into()];
    let output = client.execute_procedure_chained(procedures).unwrap();

    // output.next().unwrap();

    let public_key = output[1].clone();
    let mut first: Vec<u8> = public_key.into();
    let second: Vec<u8> = first.drain(first.len() % 2..).collect();

    // signed message used for validation further in the test
    let signed_with_original: Vec<u8> = output[2].clone().into();

    // pub-key used to derive the new location for the private key

    // Copy record to new location derived from the pub-key
    let new_location = Location::generic(first, second);
    let copy_record = CopyRecord {
        source: first_location.clone(),
        target: new_location.clone(),
    };
    assert!(client.execute_procedure(copy_record).is_ok());

    // Remove record from old location
    let vault = client.vault(first_location.vault_path());
    assert!(vault.delete_secret(first_location.record_path()).is_ok());

    // Validate by signing the message from the new location
    let sign_message = Ed25519Sign {
        msg: test_msg,
        private_key: new_location,
    };
    let signed_with_moved: Vec<u8> = client.execute_procedure(sign_message).unwrap().into();
    assert_eq!(signed_with_original, signed_with_moved);

    Ok(())
}

#[tokio::test]
async fn test_bip39_recover_zeroize() -> Result<(), Box<dyn std::error::Error>> {
    let client_path = "client-path";
    let vault_path = b"vault-path";
    let record_path = b"record_path";
    let location_a = Location::const_generic(vault_path.to_vec(), record_path.to_vec());
    let location_b = Location::const_generic(vault_path.to_vec(), record_path.to_vec());
    let passphrase = "PASSPHRASEPASSHRASE".to_string();

    let stronghold = Stronghold::default();

    let client = stronghold.create_client(client_path)?;

    let bip39_generate = BIP39Generate {
        language: MnemonicLanguage::English,
        output: location_a,
        passphrase: Some(passphrase.clone()),
    };

    let mnemonic = client.execute_procedure(bip39_generate)?;

    let bip39_recover = BIP39Recover {
        passphrase: Some(passphrase),
        mnemonic,
        output: location_b,
    };

    let pid = std::process::id();

    let result = client.execute_procedure(bip39_recover);
    assert!(result.is_ok());

    Ok(())
}

#[test]
#[cfg(feature = "insecure")]
fn test_usecase_concatkdf() {
    use crate::procedures::ConcatSecret;

    let client_path = b"client-path";

    let location_a = Location::const_generic(b"first-loc".to_vec(), b"first-loc".to_vec());
    let location_b = Location::const_generic(b"second-loc".to_vec(), b"second-loc".to_vec());
    let output_location = Location::const_generic(b"output-loc".to_vec(), b"output-loc".to_vec());

    let stronghold = Stronghold::default();
    let client = stronghold.create_client(client_path).expect("Could not create client");

    let result = client.execute_procedure_chained(vec![
        WriteVault {
            data: b"abcdefg".to_vec(),
            location: location_a.clone(),
        }
        .into(),
        WriteVault {
            data: b"hijklmn".to_vec(),
            location: location_b.clone(),
        }
        .into(),
    ]);

    assert!(result.is_ok());

    let result = client.execute_procedure(ConcatSecret {
        location_a,
        location_b,
        output_location: output_location.clone(),
    });

    assert!(result.is_ok());

    let result = client.execute_procedure(CompareSecret {
        expected: b"abcdefghijklmn".to_vec(),
        location: output_location,
    });

    assert!(result.is_ok());

    let result = result.unwrap();
    assert!(result[0] == 1, "failed: ({:?})", result);
}

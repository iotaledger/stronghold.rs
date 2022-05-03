// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    procedures::{
        ConcatKdf, DeriveSecret, GenerateKey, GenerateSecret, KeyType, PublicKey, Sha2Hash, StrongholdProcedure,
        WriteVault, X25519DiffieHellman,
    },
    tests::fresh,
    Client, Location, Stronghold,
};

#[tokio::test]
async fn usecase_diffie_hellman_concat_kdf() {
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
        .execure_procedure_chained(vec![sk1.into(), pk1.into()])
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
        .execure_procedure_chained(vec![sk2.into(), pk2.into()])
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

    client.execure_procedure_chained(procedures).unwrap();

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
#[tokio::test]
async fn concat_kdf_with_jwa() {
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
        .execure_procedure_chained(vec![write.into(), kdf.into()])
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

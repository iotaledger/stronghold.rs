// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    procedures::{
        ConcatKdf, DeriveSecret, GenerateKey, GenerateSecret, KeyType, PublicKey, Sha2Hash, StrongholdProcedure,
        X25519DiffieHellman,
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

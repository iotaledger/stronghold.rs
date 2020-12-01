// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: this module should probably not reside in the client

use crypto::{ed25519::SecretKey, macs::hmac::HMAC_SHA512};
use num_bigint::BigUint;

#[derive(Debug)]
pub enum Error {
    #[allow(dead_code)]
    NotSupported,
    CryptoError(crypto::Error),
}

// 2^252+27742317777372353535851937790883648493
// 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
#[allow(dead_code)]
fn ed25519_group_order() -> BigUint {
    BigUint::from_bytes_be(&[
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde,
        0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
    ])
}

pub struct Seed(Vec<u8>);

impl Seed {
    pub fn from_bytes(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }

    pub fn to_master_key(&self) -> Key {
        let mut I = [0; 64];
        HMAC_SHA512(&self.0, b"ed25519 seed", &mut I);
        Key(I)
    }
}

#[derive(Debug)]
pub struct Key([u8; 64]);

impl Key {
    fn I_l(&self) -> [u8; 32] {
        let mut I_l = [0; 32];
        I_l.copy_from_slice(&self.0[..32]);
        I_l
    }

    fn I_r(&self) -> [u8; 32] {
        let mut I_r = [0; 32];
        I_r.copy_from_slice(&self.0[32..]);
        I_r
    }

    pub fn secret_key(&self) -> Result<SecretKey, Error> {
        // TODO: this conversion should never fail
        SecretKey::from_le_bytes(self.I_l()).map_err(Error::CryptoError)
    }

    pub fn chain_code(&self) -> [u8; 32] {
        self.I_r()
    }

    #[allow(dead_code)]
    fn step(&self, segment: &Segment) -> Result<Key, Error> {
        if !segment.hardened {
            return Err(Error::NotSupported);
        }

        let mut data = [0u8; 1 + 32 + 4];
        data[1..1 + 32].copy_from_slice(&self.0[..32]);
        data[1 + 32..1 + 32 + 4].copy_from_slice(&segment.bs);

        let mut I = [0; 64];
        HMAC_SHA512(&data, &self.0[32..], &mut I);

        Ok(Self(I))
    }
}

#[allow(dead_code)]
struct Segment {
    hardened: bool,
    bs: [u8; 4],
}

#[allow(dead_code)]
impl Segment {
    pub fn from_u32(i: u32) -> Self {
        Self {
            hardened: i >= 2147483648,
            bs: i.to_le_bytes(),
        }
    }

    #[allow(dead_code)]
    pub const HARDEN_MASK: u32 = 1 << 31;
}

#[allow(dead_code)]
type Chain = Vec<Segment>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "verify byte-order usages"]
    // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    fn ed25519_test_vector_1() -> Result<(), Error> {
        let seed = Seed::from_bytes(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());

        // m
        let m = seed.to_master_key();
        let mut expected_master_chain_code = [0u8; 32];
        hex::decode_to_slice(
            &"90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            &mut expected_master_chain_code as &mut [u8],
        )
        .unwrap();
        assert_eq!(expected_master_chain_code, m.chain_code());

        let mut expected_master_private_key = [0u8; 32];
        hex::decode_to_slice(
            &"2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            &mut expected_master_private_key as &mut [u8],
        )
        .unwrap();
        assert_eq!(expected_master_private_key, m.secret_key()?.to_le_bytes());

        {
            // m/0'
            let ck = m.step(&Segment::from_u32(Segment::HARDEN_MASK))?;

            let mut expected_chain_code = [0u8; 32];
            hex::decode_to_slice(
                &"47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                &mut expected_chain_code as &mut [u8],
            )
            .unwrap();
            assert_eq!(expected_chain_code, ck.chain_code());

            let mut expected_private_key = [0u8; 32];
            hex::decode_to_slice(
                &"edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                &mut expected_private_key as &mut [u8],
            )
            .unwrap();
            assert_eq!(expected_private_key, ck.secret_key()?.to_le_bytes());
        }

        Ok(())
    }
}

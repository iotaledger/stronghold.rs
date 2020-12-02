// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: this module should probably not reside in the client

use crypto::{ed25519::SecretKey, macs::hmac::HMAC_SHA512};

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

#[derive(Debug)]
pub enum Error {
    NotSupported,
    CryptoError(crypto::Error),
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

    pub fn derive(&self, chain: &Chain) -> Result<Key, Error> {
        self.to_master_key().derive(chain)
    }
}

type ChainCode = [u8; 32];

#[derive(Copy, Clone)]
pub struct Key([u8; 64]);

impl Key {
    pub fn secret_key(&self) -> Result<SecretKey, Error> {
        let mut I_l = [0; 32];
        I_l.copy_from_slice(&self.0[..32]);
        // TODO: this conversion should never fail
        SecretKey::from_le_bytes(I_l).map_err(Error::CryptoError)
    }

    pub fn chain_code(&self) -> ChainCode {
        let mut I_r = [0; 32];
        I_r.copy_from_slice(&self.0[32..]);
        I_r
    }

    pub fn child_key(&self, segment: &Segment) -> Result<Key, Error> {
        if !segment.hardened {
            return Err(Error::NotSupported);
        }

        let mut data = [0u8; 1 + 32 + 4];
        data[1..1 + 32].copy_from_slice(&self.0[..32]); // ser256(k_par) = ser256(parse256(I_l)) = I_l
        data[1 + 32..1 + 32 + 4].copy_from_slice(&segment.bs); // ser32(i)

        let mut I = [0; 64];
        HMAC_SHA512(&data, &self.0[32..], &mut I);

        Ok(Self(I))
    }

    pub fn derive(&self, chain: &Chain) -> Result<Key, Error> {
        let mut k = *self;
        for c in &chain.0 {
            k = k.child_key(c)?;
        }
        Ok(k)
    }
}

pub struct Segment {
    hardened: bool,
    bs: [u8; 4],
}

impl Segment {
    pub fn from_u32(i: u32) -> Self {
        Self {
            hardened: i >= Self::HARDEN_MASK,
            bs: i.to_be_bytes(), // ser32(i)
        }
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
}

pub struct Chain(Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn from_u32(is: Vec<u32>) -> Self {
        Self(is.iter().map(|i| Segment::from_u32(*i)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestChain {
        chain: Chain,
        chain_code: &'static str,
        private_key: &'static str,
    }

    struct TestVector {
        seed: &'static str,
        master_chain_code: &'static str,
        master_private_key: &'static str,
        chains: Vec<TestChain>,
    }

    #[test]
    fn ed25519_test_vectors() -> Result<(), Error> {
        let tvs = [
            // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
            TestVector {
                seed: "000102030405060708090a0b0c0d0e0f",
                master_chain_code: "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                master_private_key: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                chains: vec![
                    TestChain {
                        chain: Chain::empty(),
                        chain_code: "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                        private_key: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0]),
                        chain_code: "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                        private_key: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0, Segment::HARDEN_MASK | 1]),
                        chain_code: "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                        private_key: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0, Segment::HARDEN_MASK | 1, Segment::HARDEN_MASK | 2]),
                        chain_code: "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                        private_key: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0, Segment::HARDEN_MASK | 1, Segment::HARDEN_MASK | 2, Segment::HARDEN_MASK | 2]),
                        chain_code: "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                        private_key: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0, Segment::HARDEN_MASK | 1, Segment::HARDEN_MASK | 2, Segment::HARDEN_MASK | 2]),
                        chain_code: "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                        private_key: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    },
                    TestChain {
                        chain: Chain::from_u32(vec![Segment::HARDEN_MASK | 0, Segment::HARDEN_MASK | 1, Segment::HARDEN_MASK | 2, Segment::HARDEN_MASK | 2, Segment::HARDEN_MASK | 1000000000]),
                        chain_code: "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                        private_key: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    },
                ],
            }
        ];

        for tv in &tvs {
            let seed = Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key();
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(&tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(&tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, m.secret_key()?.to_le_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive(&c.chain)?;

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(&c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(&c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, ck.secret_key()?.to_le_bytes());
            }
        }

        Ok(())
    }
}

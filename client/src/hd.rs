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

#[derive(Default)]
pub struct Chain(Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn from_u32<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self(is.into_iter().map(|i| Segment::from_u32(i)).collect())
    }

    pub fn from_u32_hardened<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self::from_u32(is.into_iter().map(|i| Segment::HARDEN_MASK | i))
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
                        chain: Chain::from_u32_hardened(vec![0]),
                        chain_code: "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                        private_key: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 1]),
                        chain_code: "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                        private_key: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 1, 2]),
                        chain_code: "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                        private_key: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 1, 2, 2]),
                        chain_code: "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                        private_key: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 1, 2, 2]),
                        chain_code: "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                        private_key: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 1, 2, 2, 1000000000]),
                        chain_code: "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                        private_key: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    },
                ],
            },
            // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
            TestVector {
                seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                master_chain_code: "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                master_private_key: "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                chains: vec![
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0]),
                        chain_code: "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                        private_key: "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 2147483647]),
                        chain_code: "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                        private_key: "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 2147483647, 1]),
                        chain_code: "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                        private_key: "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 2147483647, 1, 2147483646]),
                        chain_code: "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                        private_key: "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                    },
                    TestChain {
                        chain: Chain::from_u32_hardened(vec![0, 2147483647, 1, 2147483646, 2]),
                        chain_code: "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                        private_key: "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
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

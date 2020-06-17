use std::error::Error;

pub trait SecureRng {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error + 'static>>;
}

pub trait DeterministicRng: SecureRng {
    fn reseed(&mut self, seed: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}

pub trait SecretKeyGen {
    fn new_secret_key(
        &self,
        buf: &mut [u8],
        rng: &mut dyn SecureRng,
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

pub trait PublicKeyGen {
    fn get_pub_key(
        &self,
        buf: &mut [u8],
        secret_key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

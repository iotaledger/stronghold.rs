use std::error::Error;

/// a Random Number Generator
pub trait SecureRng {
    /// fills the buffer with secure random data. `buf` is the output buffer.
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error + 'static>>;
}

/// A deterministic Random Number Generator Extension
pub trait DeterministicRng: SecureRng {
    /// reseeds the random number generator with a seed.
    fn reseed(&mut self, seed: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}

/// A secret key generation algorithm
pub trait SecretKeyGen {
    /// generate a new private key in the buffer. `buf` is the output buffer.
    fn new_secret_key(&self, buf: &mut [u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>>;
}

/// A public key generation algorithm
pub trait PublicKeyGen {
    /// generate a new public key in the buffer. `buf` is the output buffer.
    fn get_pub_key(&self, buf: &mut [u8], secret_key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

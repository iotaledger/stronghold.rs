// extension on usize for constrained values.
pub trait USizeExt {
    fn constrain_value(&self) -> usize;
}

// slice extension for constrainted values
pub trait SliceExt {
    fn constrain_value(&self) -> usize;
}

impl USizeExt for usize {
    fn constrain_value(&self) -> usize {
        *self
    }
}

impl<T: AsRef<[u8]>> SliceExt for T {
    fn constrain_value(&self) -> usize {
        self.as_ref().len()
    }
}

// verify size of buffer
#[macro_export]
macro_rules! verify_keygen {
    ($size:expr => $buf:expr) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};
        
        let error = if $buf.constrain_value() != $size {
            Err("Invalid buffer size")
        } else {
            Ok(())
        };

        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

// verify auth parameters
#[macro_export]
macro_rules! verify_auth {
    ($key:expr => [$key_size:expr], => [$buf:expr, $tag_size:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $buf.constrain_value() < $tag_size => Err("Buffer is too small"),
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}
// verify encryption parameters
#[macro_export]
macro_rules! verify_encrypt {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$plain:expr => [$buf:expr, $plain_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = if $key.constrain_value() != $key_size {
            Err("Invalid key length")
        }else if $nonce.constrain_value() != $nonce_size {
            Err("Invalid nonce length")
        }else if $plain.constrain_value() > $plain_limit {
            Err("Too much data")
        }else if $plain.constrain_value() > $buf.constrain_value() {
            Err("Buffer is too small")
        }else{
            Ok(())
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}
// verify decryption parameters
#[macro_export]
macro_rules! verify_decrypt {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$cipher:expr => [$buf:expr, $cipher_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_size => Err("Invalid nonce length"),
            _ if $cipher.constrain_value() > $cipher_limit => Err("Too much data"),
            _ if $cipher.constrain_value() > $buf.constrain_value() => Err("Buffer is too small"),
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

// verify seal parameters
#[macro_export]
macro_rules! verify_seal {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_const:expr],
		$plain:expr => [$buf:expr, $plain_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_const => Err("Invalid nonce length"),
            _ if $plain.constrain_value() > $plain_limit => Err("Too much data"),
            _ if $buf.constrain_value() < $plain.constrain_value() + CHACHAPOLY_TAG => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}
// verify opening in place parameters
#[macro_export]
macro_rules! verify_open {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$cipher:expr => [$buf:expr, $tag_size:expr, $cipher_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_size => Err("Invalid nonce length"),
            _ if $cipher.constrain_value() > $cipher_limit => Err("Too much data"),
            _ if $cipher.constrain_value() < $tag_size => Err($crate::Error::InvalidData)?,
            _ if $buf.constrain_value() + $tag_size < $cipher.constrain_value() => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

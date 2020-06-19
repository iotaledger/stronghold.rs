use std::{convert::TryFrom, marker::PhantomData};

pub trait BoxProvider: Sized {
    fn box_key_len() -> usize;
    fn box_overhead() -> usize;
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;

    fn random_buf(buf: &mut [u8]) -> crate::Result<()>;
    fn random_vec(len: usize) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0; len];
        Self::random_buf(&mut buf)?;
        Ok(buf)
    }
}

pub struct Key<T: BoxProvider> {
    key: Vec<u8>,
    drop_fn: Option<&'static fn(&mut [u8])>,
    _box_provider: PhantomData<T>,
}

impl<T: BoxProvider> Key<T> {
    pub fn random() -> crate::Result<Self> {
        Ok(Self {
            key: T::random_vec(T::box_key_len())?,
            drop_fn: None,
            _box_provider: PhantomData,
        })
    }

    pub fn load(key: Vec<u8>) -> crate::Result<Self> {
        match key {
            key if key.len() != T::box_key_len() => Err(crate::Error::InterfaceError),
            key => Ok(Self {
                key,
                drop_fn: None,
                _box_provider: PhantomData,
            }),
        }
    }

    pub fn on_drop(&mut self, hook: &'static fn(&mut [u8])) {
        self.drop_fn = Some(hook)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.key
    }
}

impl<T: BoxProvider> Clone for Key<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            drop_fn: self.drop_fn,
            _box_provider: PhantomData,
        }
    }
}

impl<T: BoxProvider> Drop for Key<T> {
    fn drop(&mut self) {
        if let Some(hook) = self.drop_fn {
            hook(&mut self.key);
        }
    }
}

pub trait Encrypt<T: From<Vec<u8>>>: AsRef<[u8]> {
    fn encrypt<B: BoxProvider>(&self, key: &Key<B>, ad: &[u8]) -> crate::Result<T> {
        let sealed = B::box_seal(key, ad, self.as_ref())?;
        Ok(T::from(sealed))
    }
}

pub trait Decrypt<E, T: TryFrom<Vec<u8>, Error = E>>: AsRef<[u8]> {
    fn decrypt<B: BoxProvider>(&self, key: &Key<B>, ad: &[u8]) -> crate::Result<T> {
        let opened = B::box_open(key, ad, self.as_ref())?;
        Ok(T::try_from(opened)
            .map_err(|_| crate::Error::DatabaseError(String::from("Invalid Entry")))?)
    }
}

use engine::vault::{BoxProvider, ChainId, Key};

use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use crate::bucket::{Blob, Bucket};

pub struct Client<P: BoxProvider + Clone + Send + Sync + 'static> {
    id: ChainId,
    blobs: Blob<P>,
    _provider: PhantomData<P>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
    pub id: ChainId,
    pub keys: HashSet<Key<P>>,
    pub state: HashMap<Vec<u8>, Vec<u8>>,
}

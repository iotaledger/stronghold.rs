use crate::{bucket::Bucket, ClientId};

use serde::{Deserialize, Serialize};

use engine::vault::{BoxProvider, Key, ReadResult};

use std::collections::HashMap;

pub struct Client {
    id: ClientId,
    pub external_actor: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
    pub state: HashMap<Key<P>, Vec<ReadResult>>,
}

impl Client {
    pub fn new(id: ClientId, external_actor: Option<String>) -> Self {
        Self { id, external_actor }
    }
}

impl<P> Snapshot<P>
where
    P: BoxProvider + Clone + Send + Sync,
{
    pub fn new(state: HashMap<Key<P>, Vec<ReadResult>>) -> Self {
        Self { state }
    }

    pub fn create_snapshot(state: HashMap<Key<P>, Vec<ReadResult>>) -> Self {
        Self { state }
    }

    pub fn get_state_map(self) -> HashMap<Key<P>, Vec<ReadResult>> {
        self.state
    }
}

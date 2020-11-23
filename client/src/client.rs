use crate::ClientId;

pub struct Client {
    id: ClientId,
    pub external_actor: Option<String>,
}

// pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
//     pub id: ClientId,
//     pub keys: HashSet<Key<P>>,
//     pub state: HashMap<Vec<u8>, Vec<ReadResult>>,
// }

impl Client {
    pub fn new(id: ClientId, external_actor: Option<String>) -> Self {
        Self { id, external_actor }
    }
}

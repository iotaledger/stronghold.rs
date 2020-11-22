use crate::ClientId;

pub struct Client {
    id: ClientId,
}

// pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
//     pub id: ClientId,
//     pub keys: HashSet<Key<P>>,
//     pub state: HashMap<Vec<u8>, Vec<ReadResult>>,
// }

impl Client {
    pub fn new(id: ClientId) -> Self {
        Self { id }
    }
}

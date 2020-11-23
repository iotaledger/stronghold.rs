use engine::vault::{BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest};

use std::collections::HashMap;

use crate::line_error;

pub struct Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: HashMap<Key<P>, Option<DBView<P>>>,
    cache: HashMap<Key<P>, Vec<ReadResult>>,
}

impl<P: BoxProvider + Send + Sync + Clone + 'static> Bucket<P> {
    pub fn new() -> Self {
        let cache = HashMap::new();
        let vaults = HashMap::new();

        Self { cache, vaults }
    }

    pub fn create_and_init_vault(&mut self, key: Key<P>) -> (Key<P>, RecordId) {
        let id1 = RecordId::random::<P>().expect(line_error!());

        self.take(key.clone(), |view, mut reads| {
            let mut writer = view.writer(id1);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });

        let id2 = RecordId::random::<P>().expect(line_error!());

        (key, id2)
    }

    pub fn read_data(&mut self, key: Key<P>, id: RecordId) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        self.take(key, |view, reads| {
            let reader = view.reader();

            let res = reader.prepare_read(&id).expect(line_error!());

            match res {
                PreparedRead::CacheHit(mut v) => {
                    buffer.append(&mut v);
                }
                _ => {
                    println!("no data");
                }
            }

            reads
        });

        buffer
    }

    pub fn commit_write(&mut self, key: Key<P>, id: RecordId) {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(id);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });
    }

    pub fn write_payload(&mut self, key: Key<P>, id: RecordId, payload: Vec<u8>, hint: RecordHint) {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(id);

            let writes = writer.write(&payload, hint).expect(line_error!());

            let mut results: Vec<ReadResult> = writes.into_iter().map(|w| write_to_read(&w)).collect();

            reads.append(&mut results);

            reads
        });
    }

    pub fn revoke_data(&mut self, key: Key<P>, id: RecordId) {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(id);

            let revoke = writer.revoke().expect(line_error!());

            reads.push(write_to_read(&revoke));

            reads
        });
    }

    pub fn garbage_collect(&mut self, key: Key<P>) {
        self.take(key, |view, mut reads| {
            let deletes = view.gc();

            deletes.iter().for_each(|d| reads.retain(|r| r.id() != d.id()));

            reads
        });
    }

    pub fn list_ids(&mut self, key: Key<P>) -> Vec<(RecordId, RecordHint)> {
        let mut buffer: Vec<(RecordId, RecordHint)> = Vec::new();

        self.take(key, |view, reads| {
            let mut data = view.records().collect();

            buffer.append(&mut data);

            reads
        });

        buffer
    }

    fn take(&mut self, key: Key<P>, f: impl FnOnce(DBView<P>, Vec<ReadResult>) -> Vec<ReadResult>) {
        let mut _reads = self.get_reads(key.clone());
        let reads = _reads.take().expect(line_error!());
        let mut _view = self.get_view(key.clone(), reads.clone());
        let view = _view.take().expect(line_error!());
        let res = f(view, reads);
        self.insert_reads(key.clone(), res);
        self.insert_view(key.clone(), _view);
    }

    fn get_view(&mut self, key: Key<P>, reads: Vec<ReadResult>) -> Option<DBView<P>> {
        self.vaults.remove(&key.clone());

        Some(DBView::load(key, reads.iter()).expect(line_error!()))
    }

    fn insert_view(&mut self, key: Key<P>, view: Option<DBView<P>>) {
        self.vaults.insert(key, view);
    }

    fn get_reads(&mut self, key: Key<P>) -> Option<Vec<ReadResult>> {
        match self.cache.remove(&key) {
            Some(reads) => Some(reads),
            None => Some(Vec::<ReadResult>::new()),
        }
    }

    fn insert_reads(&mut self, key: Key<P>, reads: Vec<ReadResult>) {
        self.cache.insert(key, reads);
    }
}

fn write_to_read(write: &WriteRequest) -> ReadResult {
    ReadResult::new(write.kind(), write.id(), write.data())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket() {
        use crate::provider::Provider;

        let key = Key::<Provider>::random().expect(line_error!());

        let mut bucket = Bucket::<Provider>::new();
        let id1 = RecordId::random::<Provider>().expect(line_error!());
        let id2 = RecordId::random::<Provider>().expect(line_error!());

        bucket.take(key.clone(), |view, mut reads| -> Vec<ReadResult> {
            let mut writer = view.writer(id1);

            let wr = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&wr));

            let wr = writer
                .write(b"some data", RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            let mut wr: Vec<ReadResult> = wr.into_iter().map(|w| write_to_read(&w)).collect();

            reads.append(&mut wr);

            let mut writer = view.writer(id2);

            let wr = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&wr));

            reads
        });

        bucket.take(key.clone(), |view, reads| {
            let data: Vec<(RecordId, RecordHint)> = view.records().collect();

            data.iter().for_each(|(i, h)| {
                println!("{:?}: {:?}", i, h);
            });

            reads
        });

        bucket.take(key.clone(), |view, reads| {
            let reader = view.reader();

            let res = reader.prepare_read(&id1).expect(line_error!());

            match res {
                PreparedRead::CacheHit(v) => {
                    println!("{:?}", std::str::from_utf8(&v));
                }
                PreparedRead::CacheMiss(v) => {
                    println!("{:?}", v.id());
                }
                _ => {
                    println!("no data");
                }
            }

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let mut writer = view.writer(id1);

            reads.push(write_to_read(&writer.revoke().expect(line_error!())));

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let deletes = view.gc();

            deletes.iter().for_each(|d| {
                reads.retain(|r| r.id() != d.id());
            });

            reads
        });

        bucket.take(key, |view, reads| {
            let data: Vec<(RecordId, RecordHint)> = view.records().collect();

            data.iter().for_each(|(i, h)| {
                println!("Data {:?}: {:?}", i, h);
            });

            reads
        });
    }

    fn write_to_read(write: &WriteRequest) -> ReadResult {
        ReadResult::new(write.kind(), write.id(), write.data())
    }

    #[test]
    fn test_hashmap() {}
}

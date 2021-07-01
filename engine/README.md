## engine

Engine is the collection of low-level module with which application architects can build higher-level implementations of Strongholds for a variety of purposes. It is platform agnostic, in that it should run anywhere a Rust Compiler will work.

It is composed of 4 primary module:
- snapshot
- vault
- store
- runtime

### Snapshot

The snapshot protocol follows a fairly simple transparent pattern. Each Snapshot file follows a simple structure:

|---------------|
| magic bytes   |
| version bytes |
| header/tag    |
| --------------|
| cipher text   |
| --------------|

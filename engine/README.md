## Engine

Engine is the collection of low-level modules with which application architects can build higher-level implementations of Stronghold for a variety of purposes. It is platform agnostic, in that it should run anywhere a Rust Compiler will work.

The engine is composed of 3 primary modules:
- snapshot
- vault
- store

For more information on each of these modules, see their associated READMEs. 

### Runtime

Runtime is a crate that provides guarded types for the engine.  It is the lowest level library of the stronghold and it also defines the `ZeroingAlloc` allocator used by the entire system. Any library that implements the engine or runtime will also implement the `ZeroingAlloc` allocator by default.  For more information, see the Runtime's README.
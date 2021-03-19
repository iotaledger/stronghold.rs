# engine

https://stronghold.docs.iota.org/docs/engine/index.html

Engine is the collection of low-level crates with which application architects can build higher-level implementations of Strongholds for a variety of purposes. It is platform agnostic, in that it should run anywhere a Rust Compiler will work.

It is composed of 4 primary crates:
- snapshot
- vault
- store
- runtime

## WARNING
This library has not yet been audited for security, so use at your own peril. Until a formal third-party security audit has taken place, the IOTA Foundation makes no guarantees to the fitness of this library for any purposes.

## Example
We have an example in the `examples/commandline` folder that you can use as a reference when developing applications with Engine.

## Running tests
You can run all tests by doing the following from the `engine` directory:
```
cargo test --all
```
## Supporting the project
If this library has been useful to you and you feel like contributing, please see our contribution guidelines for all the ways in which you can contribute.

## API reference
To generate the API reference and display it in a web browser, do the following:

```
cargo doc --workspace --no-deps --open
```

## Joining the discussion
If you want to get involved in discussions about this technology, or you're looking for support, go to the #stronghold-discussion channel on [Discord](https://discord.iota.org/).

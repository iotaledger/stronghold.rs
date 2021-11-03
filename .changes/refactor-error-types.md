---
"iota-stronghold": minor
"stronghold-engine": minor
---


[[PR 269](https://github.com/iotaledger/stronghold.rs/pull/269)]
Refactor Error types in engine and client:
- Add differentiated error types for the different methods
- Avoid unwraps in the engine
- Remove the single, crate-wide used error types of engine and client
- Remove `anyhow` Error types in client and bubble up the actual error instead
- Add nested Result type alias `StrongholdResult<T> = Result<T, ActorError>` for interface errors
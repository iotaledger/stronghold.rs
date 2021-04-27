# Structure: Runtime

- [github](https://github.com/iotaledger/stronghold.rs/tree/dev/engine/runtime)
- [crates.io](https://crates.io/crates/stronghold-runtime)
- [docs.rs](https://docs.rs/stronghold-runtime)

## Stronghold Protected-access Memory Runtime.

These modules contain an interface for allocating and protecting the memory of secrets in Stronghold. Data is protected from being accessed outside of a limited scope. Instead it must be accessed via the provided interfaces.

Memory allocations are protected by guard pages before and after the allocation, an underflow canary, and are zeroed out when freed.

The primary components are:

- **Guarded** - A guarded type for protecting fixed-length secrets allocated on the heap.
- **GuardedVec** - A guarded type for protecting variable-length secrets allocated on the heap.
- **Secret** - A Type for guarding secrets allocated to the stack.
- **ZeroingAlloc** - A Zeroing Allocator which wraps the standard memory allocator. This allocator zeroes out memory when it is dropped.
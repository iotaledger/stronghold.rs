---
description: Runtime aims to provide utilities for performing computations as securely as possible with respect to the underlying operating system. The crate provides three primary Types for guarding data; GuardedVec, Guarded, and Secret.
image: /img/logo/Stronghold_icon.png
keywords:
- reference
- rust
- crate
- Guarded type
- memory
- allocated
- secret
---
import Runtime from "./../../../../../engine/runtime/README.md";

# Structure: Runtime

[![github](https://img.shields.io/badge/github-source-blue.svg)](https://github.com/iotaledger/stronghold.rs/tree/dev/engine/runtime)  [![github](https://img.shields.io/badge/rust-docs-green.svg)](https://docs.rs/stronghold-runtime) [![](https://img.shields.io/crates/v/stronghold-runtime.svg)](https://crates.io/crates/stronghold-runtime)


<Runtime/>

The primary components are:

- **Guarded** - A guarded type for protecting fixed-length secrets allocated on the heap.
- **GuardedVec** - A guarded type for protecting variable-length secrets allocated on the heap.
- **Secret** - A Type for guarding secrets allocated to the stack.
- **ZeroingAlloc** - A Zeroing Allocator which wraps the standard memory allocator. This allocator zeroes out memory when it is dropped.

---
description: Runtime extensions
image: /img/logo/Stronghold_icon.png
keywords:
- apit
- security
- runtime
- traits
- explanation
---

# Runtime extensions 


## Memory Management

Whenever a computer program requires memory to store data (e.g., some text, an image, etc. ), it must allocate memory. Allocating memory is the mechanism by which the operating system grants some of its storage and processing power to a running program to ensure that the problem can run properly.

In this context, there is also what is commonly known as "virtual memory space". Every program (process) running does not need to know the actual address in the memory but only an abstracted version.

The Stronghold runtime provides memory (speak managed allocation) types to protect sensitive data.

### Boxed Memory

`Boxed` memory locks allocated memory and prevents it from being recorded in a memory dump. Since locking memory is dependent on the operating system, the `Boxed` type relies on [Libsodium’s](https://libsodium.gitbook.io/doc/) `sodium_mlock` function. This function calls the `mlock` function on Linux (or equivalent functions on other operating systems). `mlock` prevents the current virtual address space of the process from being paged into a swap area, preventing the leakage of sensitive data. This, in turn, will be used by guarded heap allocations of memory.

Guarded heap allocations work by placing a guard page in front and at the end of the locked memory and a canary value at the front. The schematic view visualizes it.

![Guarded Heap Memory Allocations](https://i.imgur.com/oy0Ri1Z.png)

Libsodium provides three types to guard memory:

| function                    | description                                                                          |
|:----------------------------|:-------------------------------------------------------------------------------------|
| `sodium_mprotect_noaccess`  | Makes the protected memory inaccessible. It can neither be read from nor written to. |
| `sodium_mprotect_readonly`  | Makes the protected memory read-only. Memory can be read from but not written to.    |
| `sodium_mprotect_readwrite` | Enables reading from and writing to protected memory.                                |


Stronghold exposes locked memory via the `LockedMemory` trait, that exposes two functions that need to be implemented:

```rust
/// Modifies the value and potentially reallocates the data.
fn update(self, payload: Buffer<u8>, size: usize) -> Result<Self, MemoryError>;

/// Unlocks the memory and returns a Buffer
fn unlock(&self) -> Result<Buffer<u8>, MemoryError>;
```

Currently, three types of memory implement this trait:

| Type                  | Description                                                                                      |
|:----------------------|:-------------------------------------------------------------------------------------------------|
| `RamMemory`           | Allocated values reside inside the system's ram.                                                 |
| `FileMemory`          | Allocated values reside on the file system                                                       |
| `NonContiguousMemory` | Allocated memory is fragmented across the system's ram or file system, or a combination of both. |


---
description: Handling secrets at runtime with non-contigouos data types. 
image: /img/logo/Stronghold_icon.png
keywords:
- bojum scheme
- non-contiguous data types
- security
- runtime
---

<!--
This comment shall be deleted and shall give an overview on the structure:

- abstract gives an overview on memory and especially NC data types
- memory management will be explained in general, guarded types are being specifically mentioned.
   - libsodium is mentioned as low-level driving force
   - the current interface for guarded memory types is presented
- nc data types are being explained in greater detail,
- the boojum scheme is being explored with password handling as an example  
-->

# Non-Contiguous Data Types and Handling secrets at runtime

Running processes store objects in allocated memory contiguously, meaning the stream of bytes is consecutive. This is not always desirable, as an attacker could easily read sensitive information from parts of the memory. This section will describe non-contiguous memory data structures and how they work.

## Memory Management

Whenever a computer program requires memory to store data (e.g., some text, an image, etc. ), it must allocate memory. Allocating memory is the mechanism by which the operating system grants some of its storage and processing power to a running program to ensure that the problem can run properly.

In this context, there is also what is commonly known as "virtual memory space". Every program (process) running does not need to know the actual address in the memory but only an abstracted version.

The Stronghold runtime provides memory (speak managed allocation) types to protect sensitive data.

### Boxed Memory

`Boxed` memory locks allocated memory and prevents it from being recorded in a memory dump. Since locking memory is dependent on the operating system, the `Boxed` type relies on [Libsodium’s](https://libsodium.gitbook.io/doc/) `sodium_mlock` function. This function calls the `mlock` function on Linux (or equivalent functions on other operating systems). `mlock` prevents the current virtual address space of the process from being paged into a swap area, preventing the leakage of sensitive data. This, in turn, will be used by guarded heap allocations of memory.

Guarded heap allocations work by placing a guard page in front and at the end of the locked memory and a canary value at the front. The schematic view visualizes it.

![Guarded Heap Memory Allocations](https://i.imgur.com/oy0Ri1Z.png)

Libsodium provides three types to guard memory:

| function                    | description                                                                           |
|:----------------------------|:--------------------------------------------------------------------------------------|
| `sodium_mprotect_noaccess`  | Makes the protected memory inaccessible. It can neither be read from nor written to. |
| `sodium_mprotect_readonly`  | Makes the protected memory read-only. Memory can be read from but not written to.     |
| `sodium_mprotect_readwrite` | Enables reading from and writing to protected memory.                                 |


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


## Non-Contiguous Data Types

Under normal circumstances, the allocated memory is continuous and page-aligned. The operating system provides memory blocks of a minimum predetermined size. Data types that do not have a multiple of some minimum number in bytes are padded with zeroes. Metadata describes the actual fields. Operating systems take this approach to improve performance as loading some larger chunks of 2^n bytes is faster than loading the exact number of bytes.

Non-contiguous (NC) data types store their inner referenced data in multiple locations, either in memory, on the file system, or a mixture of both. NC data types are useful if the memory is partitioned into multiple segments, and storing a continuous stream of bytes might not be possible. The disadvantage is that the operating system must constantly keep track of the referenced memory segments.


### Boojum Scheme

Non-contiguous memory types split protected memory into multiple fragments, mitigating any memory dumps and making it virtually impossible for attackers to retrieve stored data. The following section describes non-contiguous memory types in more detail with a use case we often encountered and solved when we were developing Stronghold.

#### Use Case: Passphrase Management

Proper passphrase management was one of the most challenging tasks during the development of Stronghold. You need a password whenever you want to load a persistent state from a snapshot file. If you were the only user of Stronghold, and reading and writing would be interactive, providing the password each time would not be a problem. The time window in which you would use the passphrase to decrypt and later encrypt to persist a state would be small and almost non-predictable.

However, consider an application that requires constant writing into a snapshot, meaning the passphrase to encrypt the snapshot must be stored in memory. If an attacker gains access to the machine, they could dump the memory of the running process and read out the passphrase in plaintext, which of course, would be a significant security problem. Luckily, there is a solution to that called the Boojum Scheme, as described by Bruce Schneier et al. in “Cryptography Engineering”.

## Conclusion

With the new runtime, Stronghold has several options to protect sensitive data in memory. Non-contiguous types are fairly new to Stronghold. We have to figure out a good balance between performance (everything is stored in RAM) and security (fragmented across RAM and file system).

There is another limiting factor. Regarding the maximum number of protected memory regions, we empirically encountered the limit of about 8000 guarded pages on some Linux machines. To fix that, we decided to avoid storing pages inside a vault and guard them on demand instead. The amount of sensitive data at rest is presumably higher compared to sensitive data present for cryptographic procedures. Sensitive entries inside the vault at rest are encrypted with XChaCha20-Poly1305, which provides security while circumventing this limitation.
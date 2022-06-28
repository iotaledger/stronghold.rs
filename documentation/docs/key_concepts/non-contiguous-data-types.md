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

# Non-Contigouos Data Types and Handling secrets at Runtime

#### Authors: Matthias Kandora - \<matthias.kandora@iota.org>

***Abstract:***


Running processes store objects in allocated memory contiguously, meaning the stream of bytes is consecutive. This is not always desirable, as sensitive information can be easily read out from parts of the memory. Here we describe what non-contigouos memory data structures are and how they work. 

***On Memory Management*** 

Whenever a computer program requires memory to store data (eg. some text, an image, etc. ) it needs to allocate memory. By "allocating memory" we refer to a mechanism, which is given by the operating system to the running program to ensure, that some of the memory is given to the program for some purpose. In this context we also speak of "virtual memory space", as each program running ( or in computer science parlance "processs" ) does not need to know the "real" address in "real" memory, but only an abstracted / virtualized version of it.

The Stronghold runtime provides memory ( speak managed allocation ) types for handling sensitive data. One such type is `Boxed`. This type locks allocated memory and prevents it from being recorded in a memory dump. Since locking memory is dependent on the operating system, the `Boxed` type relies on libsodium `sodium_mlock` function, which calls the `mlock` function on linux or equivalent functions on other operating systems. `mlock` prevents the current virtual address space of the process to be paged into a swap area, thus preventing the leakage of sensitive data. This in turn will be used by guarded heap allocations of memory.

Guarded heap allocations work by placing a guard page in front and at the end of the locked memory, as well as a canary value at the front. The schematic view visualizes it. 

![](https://i.imgur.com/oy0Ri1Z.png)

Libsodium provides three types to guard memory:

| function                  | description                                                                                         |
|:--------------------------|:----------------------------------------------------------------------------------------------------|
| sodium_mprotect_noaccess  | This makes the protected memory inaccessible. It can neither be read from nor can it be written to. |
| sodium_mprotect_readonly  | This makes the protected memory read-only. Memory can be read, but not written to.                  |
| sodium_mprotect_readwrite | This enables reading from and writing to protected memory.                                          |


Stronghold exposes locked memory via the `LockedMemory` trait, that exposes two functions that need to be implemented:
```rust
 /// Modifies the value and potentially reallocates the data. 
 fn update(self, payload: Buffer<u8>, size: usize) -> Result<Self, MemoryError>;
 
 /// Unlocks the memory and returns a Buffer
 fn unlock(&self) -> Result<Buffer<u8>, MemoryError>;
```

Currently, the trait is implemented by three types of memory:

| Type                  | Description                                                                                                   |
|:----------------------|:--------------------------------------------------------------------------------------------------------------|
| `RamMemory`           | The allocated value resides inside the system's ram.                                                          |
| `FileMemory`          | The allocated value resides on file system                                                                    |
| `NonContiguousMemory` | Allocated memory is being fragmented either across the system's ram or file system, or a combination of both. |

***On Non-Contiguous Data Types:***

Under normal circumstances the allocated memory is continuous and page-aligned, by that we are referring to the minimim sized block of memory the (operating) system is providing us. Data types,  that may not have a multiple of some minimum number in bytes will be "padded" with zeroes. The actual fields are then described in some metadata. This is being done out of performance reasons, as loading some larger chunks of 2^n bytes is larger than loading the exact number of bytes. 

Non-contiguous (NC) data types store their inner referenced data in multiple locations either in memory, on the file system or a mixture of both. NC data types are useful, if the memory is partitioned into multiple segments, and storing a continous stream of bytes might be not be possible. The disdvantage is to always keep track of the referenced memory segments. 


***Boojum Scheme***

Non-contiguous memory types split protected memory into multiple fragments, mitigating any memory dumps and making it virtually impossible for attackers to retrieve stored data. The following section describes non-contiguous memory types in more detail with a use case we often came across and solved with a pretty decent method. 

Use Case: Passphrase Management

One of the major headaches we faced in the development of Stronghold was proper passphrase management. Whenever you need to load a persistent state from a snapshot file, you require a password. If you were a single user of Stronghold, and reading and writing would be interactive – providing the password each time – it wouldn’t be so much of a problem. The time window in which the passphrase would be used to decrypt and later encrypt to persist a state would be very small and almost non-predictable. Now consider an application that requires constant writing into a snapshot: the passphrase to  successfully encrypt the snapshot needs to be around in memory somewhere. This could be a huge problem: given that the attacker has access to the machine, they could simply dump the memory of the running process and read out the passphrase in plaintext! Horrible! Luckily there is a solution to that: It’s called the Boojum Scheme as described by Bruce Schneier et al in “Cryptography Engineering”.

*** Conclusion ***

With the new runtime we now have quite a few options to ensure sensitive data in memory is protected. Non-contiguous types are fairly new to Stronghold and we have to figure out what is a good balance between performance ( everything is in RAM ) and security ( fragmented across RAM and file system). There is another limit put by the operating system, when it comes to the maximum number of protected memory regions. On some Linux machines we encountered empirically that the limit was about ~8000 guarded pages. In order to fix that, we decided to not store guarded pages inside a vault, but guard it on demand. The number of sensitive data at rest is presumably higher compared to sensitive data being present for cryptographic procedures. Sensitive entries inside the vault at rest are encrypted with XChaCha20-Poly1305, which gives us some decent security.
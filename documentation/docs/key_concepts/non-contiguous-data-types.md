---
description: Handling secrets at runtime with non-contigouos data types. 
image: /img/logo/Stronghold_icon.png
keywords:
- bojum scheme
- non-contigouos data types
- security
- runtime
---

# Non-Contigouos Data Types and Handling secrets at Runtime

#### Authors: Matthias Kandora - \<matthias.kandora@iota.org>

***Abstract:***


Running processes store objects in allocated memory contigously, meaning the stream of bytes is consecutive. This is not always desirable, as sensitive information can be easily read out from parts of the memory. Here we describe what non-contigouos memory data structures are and how they work. 



***On Memory and Non-Contigouos Data Types:***

Whenever a computer program requires memory to store data (eg. some text, an image, etc. ) it needs to allocate memory. By "allocating memory" we refer to a mechanism, which is given by the operating system to the running program to ensure, that some of the memory is given to the program for some purpose. In this conext we also speak of "virtual memory space", as each program running ( or in computer science parlance "processs" ) does not need to know the "real" address in "real" memory, but only an abstracted / virtualized version of it.
   Under normal circumstances 


As already briefly mentioned regarding the architecture of Stronghold, the runtime provides memory ( speak managed allocation ) types for handling sensitive data. One such type is Boxed. This type locks allocated memory and prevents it from being recorded in a memory dump. Since locking memory is dependent on the operating system, the Boxed type relies on libsodium `sodium_mlock` function, which calls the `mlock` function on linux or equivalent functions on other operating systems. `mlock` prevents the current virtual address space of the process to be paged into a swap area, thus preventing the leakage of sensitive data. This in turn will be used by guarded heap allocations of memory.

Guarded heap allocations work by placing a guard page in front and at the end of the locked memory, as well as a canary value at the front. 

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
RamMemory
The allocated value resides inside the system's ram. 


FileMemory
The allocated value resides on file system


NonContiguousMemory
Allocated memory is being fragmented either across the system's ram or file system, or a combination of both. 



***Boojum Scheme***

Non-contiguous memory types split protected memory into multiple fragments, mitigating any memory dumps and making it virtually impossible for attackers to retrieve stored data. The following section describes non-contiguous memory types in more detail with a use case we often came across and solved with a pretty decent method. 

Use Case: Passphrase Management

One of the major headaches we faced in the development of Stronghold was proper passphrase management. Whenever you need to load a persistent state from a snapshot file, you require a password. If you were a single user of Stronghold, and reading and writing would be interactive – providing the password each time – it wouldn’t be so much of a problem. The time window in which the passphrase would be used to decrypt and later encrypt to persist a state would be very small and almost non-predictable. Now consider an application that requires constant writing into a snapshot: the passphrase to  successfully encrypt the snapshot needs to be around in memory somewhere. This could be a huge problem: given that the attacker has access to the machine, they could simply dump the memory of the running process and read out the passphrase in plaintext! Horrible! Luckily there is a solution to that: It’s called the Boojum Scheme as described by Bruce Schneier et al in “Cryptography Engineering”. 



*** Conclusion ***

With the new runtime we now have quite a few options to ensure sensitive data in memory is protected. Non-contiguous types are fairly new to Stronghold and we have to figure out what is a good balance between performance ( everything is in RAM ) and security ( fragmented across RAM and file system). There is another limit put by the operating system, when it comes to the maximum number of protected memory regions. On some Linux machines we encountered empirically that the limit was about ~8000 guarded pages. In order to fix that, we decided to not store guarded pages inside a vault, but guard it on demand. The number of sensitive data at rest is presumably higher compared to sensitive data being present for cryptographic procedures. Sensitive entries inside the vault at rest are encrypted with XChaCha20-Poly1305, which gives us some decent security.
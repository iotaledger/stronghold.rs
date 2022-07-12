---
description: Handling secrets at runtime with non-contigouos data types. 
image: /img/logo/Stronghold_icon.png
keywords:
- bojum scheme
- non-contiguous data types
- security
- runtime
- explanation
---```


# Non-Contiguous Data Types and Handling Secrets at Runtime

Running processes store objects in allocated memory contiguously, meaning the stream of bytes is consecutive. This is not always desirable, as an attacker could easily read sensitive information from parts of the memory. This section will describe non-contiguous memory data structures and how they work.


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
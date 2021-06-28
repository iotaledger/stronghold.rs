# Stronghold runtime system utilities

This crate aims to provide utilities for performing computations as securely as possible with respect to the underlying operating system.

The crate provides three primary Types for guarding data; `GuardedVec`, `Guarded`, and `Secret`. Here are the primary concerns centered around this library:

- guarded memory allocations
- assists with read/write protecting sensitive data
- zeroes the allocated memory when handing it back to the operating system
- uses canary and garbage values to protect the memory pages.
- leverages NACL `libsodium` for use on all supported platforms.

The `GuardedVec` type is used for protecting variable-length secrets allocated on the heap. The `Guarded` type is used for protecting fixed-length secrets allocated on the heap. The `Secret` type is used for guarding secrets allocated to the stack.

`GuardedVec` and `Guarded` include the following guarantees:

* Causes segfault upon access without using a borrow.
* Protected using mprotect:
  * `Prot::NoAccess` - when the box has no current borrows.
  * `Prot::ReadOnly` - when the box has at least one current immutable borrow.
  * `Prot::ReadWrite` - when the box has a current mutable borrow (can only have one at a time).
* The allocated memory uses guard pages both proceeding and following the memory. Overflows and large underflows cause immediate termination of the program.
* A canary proceeds the memory location to detect smaller underflows.  The program will drop the underlying memory and terminate if detected.
 * The Memory is locked with `mlock`.
 * When the memory is freed, `munlock` is called.
* The memory is zeroed when no longer in use via `sodium_free`.
 * `Guarded` types can be compared in constant time.
 * `Guarded` types can not be printed using `Debug`.
* The interior data of a `Guarded` type may not be `Clone`. `GuardedVec` includes serialization which converts the data into a vector before its serialized by serde. Upon deserialization, the data is returned back to a new GuardedVec.

The `Secret` type provides fewer security features:
* The Memory is locked with [`mlock`].
* When the memory is freed, [`munlock`] is called.
* the memory is zeroed out when no longer in use.
* values are compared in constant time.
* values are prevented from being Debugged.
* Values can not be cloned.

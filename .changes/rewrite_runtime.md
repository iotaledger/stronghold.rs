---
"runtime": minor
"vault": minor
"client": patch
---

Remove Crypto, Random and Primitives libraries in favor of Crypto.rs
Moved Runtime into the engine. 
Add new guarded types for Runtime and remove old logic. 
## Features:
* Causes segfault upon access without borrow
* Protects using mprotect
* Adds guard pages proceeding and following the allocated memory.
* Adds a canary pointer to detect underflows. 
* Locks memory with mlock.
* Frees memory using munlock
* Memory is zeroed when no longer in use through sodium_free
* Can be compared in constant time
* Can not be printed using debug
* Can not be cloned using the Clone trait.

Implement guarded types in Vault to protect the data and the keys.
Clean up logic inside of the Client library.
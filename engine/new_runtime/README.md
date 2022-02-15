# Stronghold new runtime 

This crate provides multiple types of secure memories which implementation is abstracted behind two interfaces `ProtectedMemory` and `LockedMemory`. 
These interfaces are both present in the file _src/locked_memory.rs_

## `ProtectedMemory`
Protected memory is memory which contains some "minimal" security measures such as:
- Guard areas
- Canaries 
- Constant time comparisons
- Zeroes out the memory when finished
- Access control of memory pages
- System flags against memory dumps

Values in protected memory are stored in clear. Those values are accessible by getting a reference through `borrow()` and `borrow_mut()`.
Since the values are stored in clear instances of `ProtectedMemory` should be as short-lived as possible.

`ProtectedMemory` possesses `alloc()` and `dealloc` functions.

Currently we have a single type `Buffer` implementing the `ProtectedMemory` trait.

## `LockedMemory`
Locked memory is used to store sensitive data for long period of time.
On top of having the same protections as `ProtectedMemory`, `LockedMemory` values are never not stored in clear. This means that even when scanning memory, an attacker can't read directly the sensitive data from a dump.
We currently have multiple kind of locks on `LockedMemory`:
- Encryption
- NonContiguous data structure
  - full in memory
  - split in both memory and file system
- Both at the same time

`LockedMemory` possesses `alloc()`, `dealloc`, `lock()` and `unlock()`.
To use a `LockedMemory` one needs to unlock it before.

## Ideas 
- Instead of having to unlock then lock `LockedMemory` every time, we could have a single function `exec_on_unlock()` to which we provide a closure manipulating "unlocked" memory. This is closer to the current `GuardedVec`.
  + Pros: the unlocking is done automatically at the end of the closure
  + Cons: we have some data which is encrypted and those keys are also `LockedMemory`. Therefore unlocking multiple layers of `LockedMemory` would force us to have nested closures which could be ugly. 
  + we could also provide a function `exec_on_unlock_encrypted()` that may take one/multiple `LockedMemory` keys arguments to decrypt the data
- Maybe change current implementation of `Buffer` 
  - Currently very close to `GuardedVec` using `Ref` and `RefMut`
  - Maybe get values directly by implementing `AsRef` and `AsMut` traits
    
  + `Buffer`
    * change the boxed type, implement deref and derefMut
    * implement `AsRef` 
      - we currently have an issue because `Boxed` do their own memory protection 
        management. Therefore we need concrete type `Ref` that increments 
        memory protection counter when allocating and dropping the type
  + `LockedMemory`
    * what should `dealloc()` do? remove `dealloc()`?
  + `RamMemory`
    * Reimplementation of GuardedVec, do we need all these functions?
    * Encryption 
    * Shall we allocate a new `RamMemory` every time that we `lock` it?
      - if we do: better security, worse performance
    * Serialization
  + `FileMemory`
    * async for file creation/write
  + __Encryption__
    * `box_seal` and `box_open` should use a `Buffer` in their type instead of a Vec
- __no-std__
  + Use `ArrayVec` instead of Vec no need to rely on alloc crate


# Objectives 
- [] Stable `LockedMemory` API
- [] Implementation 
  - [ x ] `Buffer`
  - [ x ] `EncryptedRam`
  - [] `EncryptedFile`
  - [] `NonContiguousMemory` 
- [] Tests
  - [] Security tests for `ProtectedMemory` and `LockedMemory`
  - [] Tests specific to new memory types
    - Test functionality 
    - Test security when locked 
    - Test if Zeroize is done correctly

# Stronghold new runtime 

This crate provides multiple ways to store data securely whether in ram, disk or fragmented into a non contiguous data structure.
All these types of memories implement the `LockedMemory` trait which enables one to allocate or unlock the data stored.
A `Buffer` type which implements basic security measures is also provided to temporarily store data for any computation.


## `Buffer`
Memory which contains some "minimal" security measures such as:
- Guard areas
- Canaries 
- Constant time comparisons
- Zeroes out the memory when dropped 
- Access control of memory pages
- System flags against memory dumps

Values in protected memory are stored in clear. Those values are accessible by getting a reference through `borrow()` or `borrow_mut()`.
Since the values are stored in clear instances of `Buffer` should be as short-lived as possible.

The main functions of `Buffer` are `alloc()`, `borrow()`, `borrow_mut`.

## `LockedMemory`
Locked memory is used to store sensitive data for longer period of times.

You can create a `LockedMemory` instance using `alloc()` or give it a new value with `update()`.
As the trait name mentions, the data stored in `LockedMemory` is _locked_ and you can retrieve using `unlock()`. Unlocked data will be returned in a `Buffer`.

When allocating a `LockedMemory` you have to choose how it will be stored and how it will be locked. 
There are 3 types that implement `LockedMemory`: `RamMemory`, `FileMemory` and `NonContiguousMemory`.

### `RamMemory`
Data will be stored in ram memory with the same security measures as the `Buffer` type.
Additionally the user can choose to have its data encrypted by providing an encryption key.

Note: `RamMemory` with non encrypted data is essentially a wrapper of the `Buffer` type.

### `FileMemory`
Data is stored in disk memory and can be encrypted.

Security measures to protect the files:
- Access control of the files (os-dependent)
- Data is mixed with noise (TODO)
- File is zeroed and removed when dropped

Note: usually disk memory is more vulnerable than ram memory but we believe that using diverse types of memories increases the data security.

### `NonContiguousMemory`
Data is split into two shards using the [Boojum scheme](https://spacetime.dev/encrypting-secrets-in-memory).
Basically the data is split into two:
- one shard is random data
- other shard is data xored with a hash of the first shard

Data is reconstructed by xoring the second shard with a hash of the first shard.

Non contiguous memory improves security through forcing an attacker to recover multiple pieces to get the original data.
User can choose to have data split in ram memory or in ram and disk (to diversify memory storage).

Moreover the shards can be _refreshed_ regularly. 
Values of the shards will be modified separately such that the original data can still be reconstructed.

Note: data in shard is xored with a hash digest, hence the data stored in non contiguous memory can only have size of a hash digest. This may seem restrictive but it fits well when following the usage recommendation described in the next section.

## Usage recommendation
Our recommendation on how to use the crate to store sensitive data.
- Data is stored encrypted in `RamMemory`
- The encryption key is stored in `NonContiguousMemory` over ram and disk

Hence data security depends on the strength of the encryption scheme and the 'obfuscation' of the encryption key in non contiguous memory.


# Objectives 
- [x] Stable `LockedMemory` API
- [x] Implementation 
  - [x] `Buffer`
  - [x] `RamMemory`
  - [ ] `FileMemory`
    - [ ] data mixed with noise
  - [x] `NonContiguousMemory` 
- [ ] Tests
  - [x] Functional correctness
  - [ ] Security 
    - [x] zeroize 
    - [ ] access to the locked memory
- [ ] Benchmarks
- [ ] no-std

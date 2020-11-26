# Stronghold runtime system utilities

A secure memory allocator and a secure computation zone abstraction

## Usage
```rust
// allocates and populates a secure memory location that can't be accessed
// unless explicitly unlocked
let st: Secure<T> = Secure::new(...);

let b = zone::soft(|| {
    // We're now in an isolated process running in a restricted zone.
    //
    // No syscalls will return except:
    // - exit and write(1) (for propagating the result to the parent)
    // - anonymous mmap (and others to support the secure memory allocator)
    // - TODO: discover and list the other uncontroversial auxillary syscalls
    //   (like clock_gettime and such)

    st.unlock(|t| {
         let a = t.decrypt();
         sensitive_operation(a)
    })
});
```

## TODOs

### Memory allocator
- [ ] mlock and a wrapper for easy lock/unlock (on drop)
- [ ] zeroize
- [ ] madvise
- [ ] canary in the offset in the first writable data page

### Computation zone
- [✓] apply seccomp
- [ ] drop capabilities
- [ ] encrypt/authenticate communication of result from child to parent
  * only relevant when the system has procfs, i.e. can get access to file descriptors
    of another process (our pipe)
  * use AES with its native instructions? what's a simple auth construct?

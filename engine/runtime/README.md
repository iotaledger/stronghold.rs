# Stronghold runtime system utilities

This crate aims to provide utilities for performing computations as securely as
possible with respect to the underlying operating system.

Among the considered concepts:

- guarded memory allocations
  - assists with read/write protecting sensitive data
  - zeroes the allocated memory when handing it back to the operating system
  - uses canary and garbage values to protect the memory pages.
  - leverages NACL `libsodium` for use on all supported platforms.

## FAQ:

### Why does my program get killed with SIGBUS/SIGILL signals?

It's common to restrict the amount of memory that can a non-privileged user can
lock into main memory (i.e. forbidden to be swapped out to disk).

The following limit is sufficient to make the tests pass:

```
ulimit -l $((1024*1024))
```

But it's quite likely that that command will fail because the system defaults
are sometimes very strict. On Arch the file that manages those limits is
[limit.conf](https://wiki.archlinux.org/index.php/Limits.conf) and the
following addition raises the limit to sufficiently run the tests:

```
username  hard  memlock 1048576
```

Note also that the tests in the crate allocates _a lot_ more memory than an
application using these runtime utilities are expected to allocate: by the
principle of least privilege only the necessary sensitive/cryptographic
operations should be performed in the most restricted sandbox.

## Low-hanging fruit

- [ ] encrypt/authenticate locked memory with a fast algorithm such as AES.

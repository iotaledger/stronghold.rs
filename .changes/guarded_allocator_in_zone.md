---
"runtime": minor
---

Add functionality to enable the guarded memory allocator in the zone when
running on POSIX (Linux, MacOS targets). The major contribution is a toggleable
memory allocator that can be used to work around rust's enforcement of only
one `#[global_allocator]`.

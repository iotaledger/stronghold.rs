# random

The random crate uses the RNG (random number generator) traits defined in the primitives crate to implement logic for a secure random number generator. A little bit of C code was used when creating this crate because all of the major platforms already have battle tested RNG libraries. This C code is bridged with Rust using CC, a `build.rs` file and Rust’s FFI (foreign function interface).  Thus far, random contains logic for Windows, MacOS, iOS, Linux, and a cavalcade of BSD flavors.

You might ask yourself, why not use an existing crate like `rand` - and the answer is that doing so allows us to bundle a closed system with very few dependencies.

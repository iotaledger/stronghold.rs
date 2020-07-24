# Crypto

The Crypto crate contains five encryption algorithms:

* Poly1305
* ChaCha20
* XChaCha20
* ChaCha20-Poly1305
* XChaCha20-Poly1305

Poly1305 and ChaCha20 were defined first which gave way to the other three variations. The internal rules were defined using Rust macros so that they would be composable. Each of these algorithms also implements some of the traits from the primitives crate which makes them extremely easy to swap out and change should the need arise.


## Fuzzing

A fuzz client was created to match the results of the library’s XChaCha20-Poly1305 and ChaCha20-Poly1305 algorithms to libsodium’s counterparts. The fuzzer has been run with up to ten billion inputs and there hasn’t been any reported variance between the implementations. XChaCha20-Poly1305 and ChaCha20-Poly1305 were used because they also verify the other algorithms indirectly.

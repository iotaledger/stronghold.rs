# Primitives

The core principle behind the primitives crate hinges upon implementing a number of traits (interfaces) which can be used to define cryptographic primitives. Each primitive contains an info data structure for describing the constraints of the algorithm and at least one trait. These primitives range from Random Number Generators to Cipher Algorithms, Hashing Algorithms and Key Derivation Functions. In this way, a developer should be able to slot in a bit of logic and have it work with the rest of the library.

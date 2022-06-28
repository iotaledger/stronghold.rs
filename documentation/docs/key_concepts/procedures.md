---
description: Cryptographic procedures
image: /img/logo/Stronghold_icon.png
keywords:
- security
- procedures
- vault
---


<!-- 
    this note can and should be deleted. 
    it's purpose is to highlight the structure of this document. 

    - the abstracts highlights the reason for the procedures framework to access secrets
    - in-depth 

--->


# Cryptographic Procedures

#### Authors: Matthias Kandora - \<matthias.kandora@iota.org>

***Abstract:***

Stronghold ensures that sensitive data cannot escape from memory that easily. This entails that you require a mechanism to actually work with secrets stored inside Stronghold's vault. Enter the cryptographic procedures framework. 

***In-Depth-Description:***


While parts of Stronghold described before were mostly concerned with writing secrets, the question arises: "what can you actually do with a secret that is never exposed? Why even store it? This is where the cryptographic procedures come into play. Stronghold features a framework to build pipelines of cryptographic operations. The pipeline pattern can be described as an abstraction over chained function calls, where each stage of a pipeline can either produce a value – eg. generate a secret (BIP39 and Mnemonic, Ed25519) – or process an existing value – e.g deriving a secret key from an existing key (SLIP10) – or export a value from an existing secret – eg. export the public key of a key pair.

The framework is abstracted in a way that combinations of simple and complex cryptographic procedures are possible. One note to mention is that custom procedures are not possible with Stronghold for a single reason: A procedure can access secrets, providing a custom procedure that exposes a secret and returns it, would violate the Stronghold core principle. 

The procedures framework is build upon a pipeline pattern, where each stage is only given the location inside the vault to access or work with secret data. The schematic showcases the generation of a public / private keypair that gets stored in `location1`, the next stage takes the previous `location1` and derives a new keypair to store it in `location2`, eventually the last stage takes `location2`, extracts the public key and returns it to some publicly accessible data. 

![https://viewer.diagrams.net/?tags=%7B%7D&highlight=FFFFFF&edit=_blank&layers=1&nav=1&title=pipeline#R7Vldb6M4FP01eZzI2JDAY9t0u1JnpEp92Jl9c8ED3nEw45gm7K%2Ff62K%2BG5o2JO1oFlUq9%2Fr6g3PPPQZnRq7WuxtFs%2BSLjJiYYRTtZmQ1w9hxMZ6ZPxQVpWcZkNIRKx7ZoMZxz%2F9l1omsN%2BcR23QCtZRC86zrDGWaslB3fFQpue2GfZeiO2tGYzZw3IdUDL1%2F8Ugnpdf3UOP%2Fk%2FE4qWZ2kG1Z0yrYOjYJjeS25SLXM3KlpNTl3Xp3xYQBr8Kl7PfHntZ6YYql%2BpAOJL1lwrveZTcX%2BGex8i7p37efHJuNRypy%2B8QzvBAw4GXEHw2GgsfpU8PiZ26WeqmenrY24S42%2Fx9pLnTVF1bx1L1sss%2BviwpUJfM0YmZdCJq3CdfsPqOhad0CjcCX6LUAy4HbagXlvDARU5pDgi6s%2F0FqLdfQsNFK%2FqizRMDznQtxJYVUYKcyZfVa2qhZIM2wbNdyWRRvmFwzrQoIsa0Lm1DL6NreNvzwKhYkbW5UgdRyMq6HbtIGNzZzr8nicjyLZRoyJUMW5QrKCSOWxhwAsVEPqsnV9Bl8Jg0HJ3X6fDkH5wudLF%2FBAFAWgexYUyqdyFimVFw33ssGcoNpE%2FNZysw6%2F2FaF1ZDaa5lNw2AoCq%2Bto1vJn9zrzJXO5vP0ioqa8f116dI7FnzWzUK3De9jFF12pu3jcxVyMbAsSpPVcz0WJxfBhrkRmmgmKCaP3YF%2Fbmc2q53ksOaa%2FrUNKjq3XW7Q5RPZHs1zLhQihatsMwEbEbmcXrz%2BD09f1083JQraGhaY%2FJ25uLFUcxFRzIXvY65pyehNzUHj9OVwTZww1KmqAahR7esuKNcHSflE8ix35PjYCjHDn5Gjt1TqTH2fk01PocYewfWQTXgxGL8Wg0lfa1ejGvoC%2FEn0tDl76Ghh3In%2BFAa6g00dMUUzAry%2Be7SWWvgh9FOggagnFM70Txwgx6fXfySghrrDpIKEDB1NM2DQyVycp6%2FSSLd%2Fv5LxiXSC46LX5DTK2owqFkIAF6B7y5%2FEDx898p10UerXOy%2Bc%2BVir124zktFW7%2F2uMtl%2B8Vnjshi9OXHGNNVe%2FXVef4vgzdVO152eUc8fPpyrDAaP44SMoQHlykEOqc4dVJSl%2BOT1adgNOmHl3EfTTKsYv%2BsRTz84htHGv8qSPdP7d4f6uEmk9m9BUVU06GaCsGzjVHNTUIz4wyFzKOX4eyeY%2B85QJ0AYtLbqfGBW5J%2FspdJZwji%2F1vS%2Bb%2Bf9nwrYzRH7WvR21mcuU%2BC%2BvK74%2B85JB2%2Bnnr%2B3OuODESdB%2B2rO3KJz9HHry6ZdKcEs%2FlprwxvfiAl1%2F8B](https://i.imgur.com/qZ5QX23.png)

The pipeline pattern knows of three kinds of primitives:

1. A `Generator` / `Source` that produces secret keys or seeds and does not take any inputs, and in most cases produces either a keypair ( eg. Ed25519 ) or a mnemonic ( BIP39 ) to create a seed for a determinsitic wallet
2. A `Processor` takes in locations or data, and produces some new secret, stores it in a location and is normally used to derive a new keypair (SLIP10). 
3. A `Receiver` / `Sink` that takes a location, produces a value and returns it, but does not store any product inside the vault.


All operations involving sensitive data make heavy use of the procedures framework.

***Code Example***

```rust
//  .. we initialize `client` somewhere before the calls


// This constructs a `GenerateKey` procedure, that will generate a key at given
// output location in the vault
let generate_key_procedure = GenerateKey {
       ty: keytype.clone(),
       output: output_location.clone(),
};
 
// Even though this procedure does not create a useful output, the result can be
// used to check for errors
let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));
 
// Front the previously generate key, we want to export the public key
let public_key_procedure = stronghold::procedures::PublicKey {
       ty: keytype,
       private_key: output_location,
};
```



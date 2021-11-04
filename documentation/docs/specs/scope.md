---
description: Stronghold is a secure software implementation with the sole purpose of isolating the seed, private keys, personally identifiable information (PII) and policy records from exposure to the genuinely hostile environment of user devices.
image: /img/logo/Stronghold_icon.png
keywords:
- rust
- private key
- High level library
- Actor Model layer
- low level libraries
- Secure Element
- libraries
---
# Specification: SCOPE

# Project Scope (Scope){#scope}
[Scope]: #Scope

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Stronghold
stub: stronghold
document: SCOPE
version: 0000
maintainer: Daniel Thompson-Yvetot <daniel.yvetot@iota.org>
contributors: [tensorprogramming <tensordeveloper@gmail.com>, Daniel Thompson-Yvetot <daniel.yvetot@iota.org>]
sponsors: [Navin Ramachandran <navin@iota.org>]
licenses: ["Apache-2", "CC-BY-INTL-3.0"]
updated: 2021-Apr-27
```

## License
[license]: #license
<!--
Please specify licenses here and in the frontmatter.
-->
All code is licensed under the Apache-2 license, all text and images are licensed under the CC-BY-INTL-3.0 license.

## Language
[language]: #language
<!--
Do not change this section.
-->
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Versioning
[versioning]: #versioning
<!--
Do not change this section.
-->
These documents MUST use incremental numbering. New documents always start at 0000. Subsequent revisions to each RFI, RFP and RFC will have their number increased by one.

Software releases will follow [strict semantic versioning](https://semver.org/).

## Hierarchy
[hierarchy]: #hierarchy
<!--
Do not change this section.
-->
All documents in this specification are understood to flow from this document and be bound to its licenses and language as described above.

## Summary
[summary]: #summary
Stronghold is a secure software implementation (often used in conjunction with - or existing purely on - specialist hardware) with the
sole purpose of isolating the seed, private keys, personally identifiable information (PII) and policy records from exposure
to the genuinely hostile environment of user devices. It uses snapshotting and internal mechanisms for threshold signature
schemes that MAY be distributed across devices.

It is based on a suite of low-level libraries collectively called "engine" that provide tooling and algorithms to build secure systems
in Rust in a way that can be embedded and deployed to cross platform devices. Engine is a collection of libraries which deal with the
obfuscation and sharing of secret values both mutable and immutable between devices.

The primary task is to isolate the activity of “privileged” functions from other parts of the software stack. For example, a primary
goal is to create a software enclave where private keys are used to sign messages without revealing those keys to other functions.

Additionally, a system for enabling Stronghold-based systems to securely communicate with each other shall be created such
that devices on different networks can collaborate cryptographically.

## Motivation
[motivation]: #motivation
### Research
Coming on the heels of the Trinity attack, it became clear that a new method for securing secrets needed to be manufactured and made
available to the pantheon of IOTA Products.

### Market opportunities
- Integration with the Wallet, Nodes, Identity, Access and developer toolchains strengthens IOTA’s internal position.
- Publishing the low-level libraries will enable third-parties interested in secure rust-based systems will expand the visibility
of IOTA in the security community.

### Alignment with mission
- Creating and maintaining open source software, and providing educational opportunities is the core mission of the IOTA Stiftung.

### Current resources/technology
- Using off-the-shelf libraries has always been a trade-off. Writing the library in Rust using as few external dependencies as
possible is a good baseline. Designing the library such that cryptographic primitives can be replaced will make the library viable
in the long-term.

## Product Introduction{#product}
[product]: #product
### Business Application Benefits
- Enhance the security posture of critical IOTA Products
- Enhance the perception of the IF as a “security-focussed” organisation.
- Create new avenues for partnership and 3rd party implementation.

### Technical Benefits
- Writing in rust gives a number of memory-safety benefits
- Fuzzing from the beginning improves confidence of software fitness
- Providing reference implementation gives assurance to integrators

### Educational Benefits
- Rust is a single source of code truth is a practice that the IF is interested in.
- Helping developers new to IOTA use a secure system from the beginning is a good way to train.
- Learning about Fuzzing is useful for all developers.

## Stakeholders
[stakeholders]: #stakeholders
A number of IOTA foundation stakeholders have been involved in the design process, ranging
from Engineering to Product and developer outreach.

## Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

Stronghold itself has several core components:

### 1. Low level libraries (engine.rs)

There are 5 low level libraries:
- crypto (swappable crypto implementation, chacha20poly1305 & salsa20)
- primitives (shared structs and traits)
- random (secure implementation of random)
- snapshot (stateful storage management)
- vault (interaction with storage)

This work has been undertaken by an external developer in the context of an EDF grant using
prior work from Daniel Thompson-Yvetot and Tensor at their security boutique "IONARY".

### 2. High level library (stronghold.rs)

The high level library integrates engine.rs and iota.rs to a fully fledged secret storage and
enclave based system for operations in the context of the IOTA Protocol.

Its primary purpose is to serve as the operational enclave for several IOTA Products:
- Wallet
- Identity

This work will be undertaken in house by IOTA developers.

### 3. Actor Model layer

The Actor Model layer is a thin wrapper for message parsing and message sending that is
built for interaction with the wallet and any other projects that deem the actor model
suitable to their needs.

This work will be undertaken in house by IOTA developers.

## Prior art
[prior-art]: #prior-art
There is a massive amount of prior art.

### Trinity
The official IF wallet, available on Android, iOS, MacOs, Windows, Linux. It uses React as a front-end language,
Electron as a backend for Desktop platforms and React native as the backend for Mobile devices.

### Nano Ledger
A hardware token storage system that uses two STM chips (ST31 for secure storage [presumably]) and the STM32
for actual processing.

### Cryptocore
“The CryptoCore is IOTA hardware designed for applications that need fast, dedicated proof of work and a secure
memory. The device consists of an IOTA CryptoCore FPGA (ICCFPGA) module and a development board that doubles as a
Raspberry Pi HAT, making it perfect for standalone applications and/or quick prototyping.“

### WeChat MiniPrograms
WeChat is a chat and payment application very popular in the Chinese market. MiniPrograms run inside of the scope
of the main application.

### JSbox
JSBox is an iOS centric system for running JS in an iOS application developed primarily for the Chinese market.
It is an application on the iOS Store geared toward developers:

“JSBox is not only a full-fledged environment for standard JavaScript, but also provides many utilities:

- A safe environment to run JavaScript natively with incredible performance
- A beautiful editor to write JavaScript, multiple themes, auto-completion, and snippets...
- Many advanced development tools: lint, prettier, diff viewer and database viewer...
- A desktop extension to write code extremely fast and comfortable
- Almost all the cool tech in iOS: Siri/Shortcuts, Today Widget, Action Extension, 3D Touch, Home Screen Shortcut...
- A lot of awesome examples for beginner”

### Tauri (Kamikaze Pattern)
The Kamikaze pattern uses a system of event listeners and emitters in Rust and in Webview that communicate with
each other using throwaway handles. Considered by the Tauri team to be the most secure pattern possible.

### Titan / OpenTitan
Open source security chip from Google available in the Pixel 3 (and other security dongles), which enables secure
booting of mobile devices and provides a “secure” keystore for Third Party apps. Please review CVE-2019-9465 for a
somewhat troubling “non-disclosure”. OpenTitan is the “community” project for an open hardware “Root of Trust”.

### OpenSK
Rust based security firmware for Nordic from Google.
“Under the hood, OpenSK is written in Rust and runs on TockOS to provide better isolation and cleaner OS
abstractions in support of security. Rust’s strong memory safety and zero-cost abstractions makes the code less
vulnerable to logical attacks.”

### iOS Secure Enclave
“When you store a private key in the Secure Enclave, you never actually handle the key, making it difficult for
the key to become compromised. Instead, you instruct the Secure Enclave to create the key, securely store it, and
perform operations with it. You receive only the output of these operations, such as encrypted data or a
cryptographic signature verification outcome.”

### Gatekeeper
The official MacOS Application verifier and Anti-Malware service verifies integrity and developer signatures,
and manages the “quarantine” flag on downloaded files.

### Riddle&Code Secure Element
“The Secure Element 2.0 generates a unique private key that cannot be rewritten over the lifetime of the chip.
The stored private key can only be used within computations of the microchip itself.
It employs a highly-secure hardware-based cryptographic key storage and cryptographic countermeasures which
eliminate potential backdoors linked to software weaknesses. Thus, ensuring that the key cannot be exfiltrated.
The decryption of data is only run on the chip itself and happens “off-the-bus”. Thereby, leaving an absolutely
minimised attack surface for attackers trying to compromise the private key.”

> this does not address concerns with the onboard RNG, the Secure Element in use is EOL.

### Cryptosteel
“The Cryptosteel Capsule is the premier backup tool for autonomous offline storage of valuable data without any
third-party involvement. The solid metal device, designed to survive extreme conditions, works under nearly all
circumstances.”


### VST / LADSPA / LV2 Plugins
These audio plug-in systems use digital signal processing, come with a back-end, a front-end, presets and
interface with a larger system. They generally require a host. Of special interest is the architectural design
pattern of LV2:

“The host program loads the plugin, and calls some initialization functions. The host can provide a list of
LV2_Extension that it supports when it initializes the plugin, so the capabilities of the host are known to
the plugin when it is started. Similarly, the plugin uses Turtle metadata to provide a list of capabilities
to the host, so the host can accommodate those. This capability concept is very powerful, but also difficult
to understand at first. ‘Atom’ messages are sent between plugin event ports, and this mechanism is used to
transfer MIDI, OSC and Patch information between plugin instances.”

Here is an example of a VST Builder written in rust.
Here is a solution for building a dylib for MacOS, and the accompanying “base plugin”.

### TEE / TrustZone
Trusted Execution Environments can be considered to be a “secure zone” of a processing unit. Generally more
powerful than a Secure Element, their architecture isolates processes such as boot and analyzing application
integrity. Obviously there are standards and any number of vendor implementations.

### Binary Obfuscation
Here is a collection of research about Binary Obfuscation approaches:
Sean Taylor presentation at DefCon
Seminal Paper on Functional Obfuscation (see Multilinear Jigsaw)
Runtime Encryption (hyperion)
https://nullsecurity.net/tools/cryptography.html
http://phrack.org/issues/63/13.html <- Excellent Writeup
This idea of finger printing the system is especially appealing. When adding more than one device with
"entangled" setups; deriving multiple fingerprints or a fingerprint that runs on multiple devices might be
possible.

https://github.com/packz/binary-encryption/tree/master

Links from Tensor:
- https://github.com/obfuscator-llvm/obfuscator/wiki
- https://repo.zenk-security.com/Reversing%20.%20cracking/HARES:%20Hardened%20Anti-Reverse%20Engineering%20System.pdf
- http://www.freepatentsonline.com/8145900.html
- https://github.com/andrivet/ADVobfuscator
- https://github.com/rootm0s/Protectors


### Dashpay BLS threshold and DKG
- https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md
- https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
- https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f?gi=1111957aa919

### Pillar
Smart contract wallet
- https://medium.com/pillarproject/understanding-plr-utility-part-i-pillar-smart-wallet-personal-data-locker-6138bb3058b5

### HashD
See Section 6 on Identity Recovery
https://blog.hashd.in/hashd-in-draft0/

### Fireblocks
Fireblocks is a multisig system. Dom has more information about them.
https://www.fireblocks.com/

### Vault12
“Using a secure decentralized network made up of trusted people, Vault12 gives cryptocurrency owners the peace
of mind that their crypto assets remain backed up, cryptographically secure but accessible regardless of
threats such as attacks on centralized servers and digital impersonation.”
https://vault12.com/

### EMQ Rule Engine
https://github.com/emqx/emqx-rule-engine/blob/master/docs/design.md

### MESALINK
MesaLink implements OpenSSL C APIs with Rust FFI. If you call an exported C FFI function from Rust, it’s no
different to calling that same exported C function from a different C or C++ library. Unlike Java/Go, there
is zero overhead.
https://mesalink.io/faq/

### Non-bypassable Security Paradigm
https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/documents/nbsp.pdf

### RSIGN2
minisign in wasm from Rust
https://wapm.io/package/jedisct1/rsign2

### Single Use Seals
https://petertodd.org/2017/scalable-single-use-seal-asset-transfer

### Others
https://guardtime.com/mida/
https://www.riddleandcode.com/secure-element
https://github.com/RiddleAndCode/secure-element-sdk/wiki/Raspberrypi-HSM
https://safenetwork.tech/faq/#what-is-self-authentication
https://keycard.tech/

## Unresolved questions
[unresolved-questions]: #unresolved-questions

<!--
- What parts of the design do you expect to resolve through the spec process
before this gets merged?
- What parts of the design do you expect to resolve through the implementation
of this product?
- What related issues do you consider out of scope for this prodect that could
be addressed in the future independently of the solution that comes out it?
-->

## Future possibilities
[future-possibilities]: #future-possibilities
- Having a CLI
- Having a service that can run as a daemon
- Using a remote stronghold


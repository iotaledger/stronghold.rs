---
description: 'Stronghold is an open-source software library which can be used to protect any digital secret. It is a
secure
database for working with cryptography, which ensures that secrets are never revealed - but can be used according to
best practices.'
image: /img/Banner/banner_stronghold.png
keywords:

- welcome
- open-source
- secure
- secrets
- database

---

# Welcome

![Stronghold](/img/Banner/banner_stronghold.png)

Stronghold is an open-source software library that was originally built to protect IOTA Seeds, but can be used to
protect any digital secret.

Stronghold is a secure database for working with cryptography, which ensures that secrets (like private keys) are never
revealed, but can be used according to best practices.

Stronghold can be seen as some kind of isolated container for secrets that may be either a private key, or some other bytes of data, that should never be exposed. In order to work with Stronghold one uses  so called procedures to either generate new keys, store data into the vault, derive keys or work with the data in place. The difference to a "traditional" password store is, that secret data is never accessed directly but can be worked with the aforementioned procedures. Whenever there is a need to sign some data with a private key, one would be required to call a respective function to work with it. 

Generally speaking there are two states where the secret data remains. The runtime operation makes use of Clients. Clients can be thought of as a context-based secure data container with all the functionality to work with sensitive data. In order to persist the runtime data, there are the Snapshot facilities. The Snapshot is actually twofold. At the lowest level, the Snapshot is a highly encrypted file which is being represented by an in-memory instance of Snapshot itself, which itself is encrypted and protected via the same means as the Vault.

Additionally to the secure `Vault` type, Stronghold provides an eviciting cache to store non-sensitive data called the `Store`. Use the `Store` to keep session based configuration data. 

[![status](https://img.shields.io/badge/Status-Beta-green.svg)](https://github.com/iotaledger/stronghold.rs)
![Audit](https://github.com/iotaledger/stronghold.rs/workflows/Audit/badge.svg?branch=dev)
![Test](https://github.com/iotaledger/stronghold.rs/workflows/Test/badge.svg)
[![docs](https://img.shields.io/badge/Docs-Official-green.svg)](https://stronghold.docs.iota.org)
[![coverage](https://coveralls.io/repos/github/iotaledger/stronghold.rs/badge.svg?branch=dev)](https://coveralls.io/github/iotaledger/stronghold.rs?branch=dev)
[![dependency status](https://deps.rs/repo/github/iotaledger/stronghold.rs/status.svg)](https://deps.rs/repo/github/iotaledger/stronghold.rs)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs?ref=badge_shield)

## 3rd Party Independent Security Audit

In April 2021, F-Secure performed a security assessment of the core crates of IOTA Stronghold and found nothing of
concern. This is not an explicit declaration of fitness or freedom of error, but it is an indicator of the high quality
of the code. You may review in our
[GitHub repository](https://github.com/iotaledger/stronghold.rs/blob/dev/documentation/docs/meta/Audit.pdf).

In May 2022 Stronghold was also audited by [WithSecure](https://www.withsecure.com/en/home). You can find the full
audit report in our
[GitHub repository](https://github.com/iotaledger/stronghold.rs/blob/dev/2022-05-04-IOTA-Stronghold-statement-of-work-performed-1.pdf)
.

## Joining the discussion

If you want to get involved in discussions about this library, or you're looking for support, go to the
#stronghold-discussion channel on [Discord](https://discord.iota.org).

## Software Bill of Materials

We maintain a [bill of materials](https://github.com/iotaledger/stronghold.rs/raw/dev/S-BOM.pdf) for the upstream
libraries that Stronghold consumes. 



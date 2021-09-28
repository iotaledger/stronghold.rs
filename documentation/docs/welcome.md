---
description: Stronghold is an open-source software library can be used to protect any digital secret. It is a secure database for working with cryptography, which ensures that secrets are never revealed - but can be used according to best practices.
image: /img/logo/Stronghold_icon.png
keywords:
- open-source
- secure
- secrets
- Noise
- database
- p2p
---
# Welcome
Stronghold is an open-source software library that was originally built to protect IOTA Seeds, but can be used to protect any digital secret. 

It is a secure database for working with cryptography, which ensures that secrets (like private keys) are never revealed - but can be used according to best practices.

It provides its own peer-to-peer communication layer, so that different apps can securely communicate using the state-of-the-art Noise Protocol over libp2p. 


[![status](https://img.shields.io/badge/Status-Beta-green.svg)](https://github.com/iotaledger/stronghold.rs)
![Audit](https://github.com/iotaledger/stronghold.rs/workflows/Audit/badge.svg?branch=dev)
![Test](https://github.com/iotaledger/stronghold.rs/workflows/Test/badge.svg)
[![docs](https://img.shields.io/badge/Docs-Official-green.svg)](https://stronghold.docs.iota.org)
[![coverage](https://coveralls.io/repos/github/iotaledger/stronghold.rs/badge.svg?branch=dev)](https://coveralls.io/github/iotaledger/stronghold.rs?branch=dev)
[![dependency status](https://deps.rs/repo/github/iotaledger/stronghold.rs/status.svg)](https://deps.rs/repo/github/iotaledger/stronghold.rs)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs?ref=badge_shield)


## 3rd Party Independent Security Audit
In April of 2021, F-Secure performed a security assessment of the core crates of IOTA Stronghold and found nothing of concern. This is not an explicit declaration of fitness or freedom of error, but it is an indicator of the high quality of the code. You may review [the audit here](https://github.com/iotaledger/stronghold.rs/blob/dev/documentation/docs/meta/Audit.pdf).

## Joining the discussion
If you want to get involved in discussions about this library, or you're looking for support, go to the #stronghold-discussion channel on [Discord](https://discord.iota.org).

## What you will find here
This documentation has six sections. 

1. **The Overview**: detailed overview of the project
2. **Structure**: explains the layout of the individual crates and systems
3. **The Specification**: detailed explanation of requirements and functionality
4. **Retrospective**: a look at the evolution of this project
5. **Contribute**: how you can participate in the Stronghold software development
6. **Get in touch**: join the community and become part of the X-Team

## Software Bill of Materials
We maintain a bill of materials for the upstream libraries that Stronghold consumes. You can download the latest version of that here:

https://github.com/iotaledger/stronghold.rs/raw/dev/S-BOM.pdf

## Tutorials (Coming Soon)

We will be adding video and textual tutorials for introducing the concepts behind Stronghold.

## How To's (Coming Soon)

We will be adding a number of specific How To examples that will cover common use cases, like integrations, backups etc.
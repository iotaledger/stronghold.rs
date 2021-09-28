---
description: This document introduces the high-level specification of Stronghold.
image: /img/logo/Stronghold_icon.png
keywords:
- rust
- high level 
- low level
- library
---
# Stronghold Engineering Specification {#engineering-spec}
[engineering-spec]: #engineering-spec

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Stronghold
stub: stronghold
document: Engineering Specification
version: 0000
maintainer: Daniel Thompson-Yvetot <daniel.yvetot@iota.org>
contributors: [Dave de Fijter <dave.defijter@iota.org>, tensorprogramming <tensordeveloper@gmail.com>, Daniel Thompson-Yvetot <daniel.yvetot@iota.org>, Marcelo Bianchi <marcelo.bianchi@iota.org>]
sponsors: [Navin Ramachandran <navin@iota.org>]
licenses: ["CC-BY-INTL-3.0"]
updated: 2021-Apr-27
```

## Summary {#summary}
[summary]: #summary

This document introduces the High-Level Specification of the Stronghold.

## Logical System Design {#system-design}
[system-design]: #system-design

### Low Level
A Stronghold is composed of several interacting systems at a low level:

1. Snapshot - box-encrypted file-based persistence layer
2. Vault - a write and use protected, path-based system for storing and using secrets like private keys
3. Store - a read/write key:value storage system for dynamic data 
4. Cache - an in-memory abstraction for vault and store
5. Runtime - memory protection system for secrets
6. Communication - libp2p based system for communication between strongholds

### High Level
At the high level, Stronghold provides an official client for interfacing with a Stronghold snapshot and its records.


# Wallet Requirements: Request For Proposals (RFP)
[RFP]: #RFP

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Stronghold
stub: stronghold
document: SCOPE
version: 0000
maintainer: Daniel Thompson-Yvetot <daniel.yvetot@iota.org>
contributors: [tensorprogramming <tensordeveloper@gmail.com>, Daniel Thompson-Yvetot <daniel.yvetot@iota.org>]
sponsors: []
licenses: ["MIT/Apache-2", "CC-BY-INTL-3.0"]
updated: 2020-MAY-29
```

<!--
A Request For Proposals is an open question that seeks to focus research and development in the prealpha phase
and is based on needs defined in the Project Scope document.
-->

## Summary
[summary]: #summary
<!--
Summarise in 3-5 sentences in normal English what it is that proposals in this context should address.
-->
### Wallet Security Requirements
The use case of the wallet will require a number of solutions, many of which need to be supported by
Stronghold. Here is a current list:

## Requirements
[requirements]: #requirements

The following are security requirements as proposed by the wallet team.
###
```
SNAPSHOTS
- Snapshot Import
- Snapshot Export
- Splitting the snapshot
  - Custodians, nominate with redundancy
  - Share the shardshots on a regular basis
- Drag and Drop import
- Can Stronghold be used as the digital backup for your seed?
  - Password (?)
  - Decryption key (?)

SEEDS
- Seed Entry
- Import from Trinity
- Panic Button for “At Risk Concerns”
- Seed Backup
  - Physical (written down) seed mnemonic (we are all against this, btw)
    - Requires display to the user
    - Requires later reentry for recovery
- Ability to skip backup and enter wallet,
  but prompted with reminders when trying to do sensitive actions

APP LOCK
Standard user
- Desktop
  - Password (11 chars)
  - MFA via mobile / Yubikey
-	Mobile
  - Password, option to skip and use biometric/pin only
  - Variable app lock settings: require for app access / require for transactions

INTERNALS
- Multi tenant
- MFA with 2nd Device
- Handoff to Ledger

Security Settings Overview (SHIELD)
Notifications
```


## Considerations
[considerations]: #considerations
<!--
This section can be used if there are known considerations that need to be taken into account and which the actual proposals SHOULD resolve.
-->

## Technical Proposal
[technical-proposal]: #technical-proposal
<!--
Introduce and explain the technical proposals that are being requested, detailing specifically the individual proposals required.
-->

## Research
[research]: #research
<!--
Please collect all relevant research links to repositories, issues and papers
-->

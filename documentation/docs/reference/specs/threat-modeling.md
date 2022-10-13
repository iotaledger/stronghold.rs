---
description: Discover how Stronghold  
image: /img/logo/Stronghold_icon.png
keywords:
- threat modeling
- security
- explanation
---

# Stronghold Threat Modeling 

As a security software Stronghold has to do its best to prevent 
attackers to access the secrets that it stores.
Threat modeling is a systematic approach that try to assess all the potential 
attack scenarios that can happen on a software.
The process is divided into multiple steps:
- model your software 
- define the assets and security property you protect
- list potential threats using existing classification (STRIDE in our case)
- propose mitigations to those threats

## Model of Stronghold
Stronghold concept is simple. 
Stronghold is used to store secrets. 
Secrets should never ever be revealed even to their owners. 
Users can interact with secrets through a controlled set of methods called _procedures_.

### Typical use of Stronghold:
1. Generate a key in Stronghold
2. Use Stronghold procedures to use the key for: encryption, decryption, signatures... 
3. Store Stronghold state for future usage in permanent storage called Snapshot 


### Model 
![Stronghold model](./assets/stronghold_model.drawio.png)

- Users can only interact with secrets through the procedures API.
- Users can only use procedures on the secrets they own
- Procedures cannot reveal/temper secrets (can delete them though) 
- Secrets can be kept permanently in an encrypted form in a Snapshot (filesystem)

## Assets
The sole asset of Stronghold are the secrets.

High importance
- __Confidentiality__: secrets are never revealed
- __Integrity__: secrets cannot be modified (except deletion)
- __Authentication__: secrets can only be interacted with authorized users

Mid importance
- __Availability__: a user is able to interact with its secrets at any time

Low importance
- __Least privilege__: there are no privileged users in Stronghold
- __Non-repudiation__: user can't disprove that it has used a procedure on a secret 

## Attack surface 
We try to defend against multiple type of attackers.
Levels also represent how likely for such attacker to appear.
- __Level 1__: Procedure API 
- __Level 2__: Permanent storage: Snapshot in the filesystem
- __Level 3__: Memory
  - the attacker is able is to read memory 
  - through cold-boot attacks or memory dumps
- __Level 4__: Side-channels
  - timing attacks
  - power consumption
  
Also a type of attacker that we don't represent here but is also important comes from potential vulnerabilities that come from the tools used to build the software.
- __Bonus__: Tools
  - Packages
  - Rust language 
  - Compilation
  - Crypto algorithms used


## Potential threats STRIDE
We use the [STRIDE](https://owasp.org/www-community/Threat_Modeling_Process) threats classification. 
Stride is applied to all the types of attacks listed [above](#attack-surface).
Mentions of __WIP__ means that it is still "Work In Progress".



### Level 1: Procedure API
| Attack | Attack | Remediation | Severity |
| -------- | -------- | -------- | ----- |
| Spoofed  | An unauthorized user executes some procedures | When restoring Stronghold state from a snapshot a key is required to decrypt the snapshot | High |
| Tampered  | Secrets are tampered using procedures | Procedures are developed and audited by the team to not modify secrets | High |
| Repudiated | User is accused to have used secrets maliciously/incorrectly | Log all the procedures that have been processed (WIP) | Low |
| Information Disclosure | Secret is revealed through procedures | Procedures are developed and audited by the team to not reveal secrets | High |
| Denial of Service | Spamming procedures to block the system | Software that uses Stronghold responsibility | Mid |
| Elevation of Privileges | None, no privileged users in Stronghold | | |


### Level 2: Permanent Storage, file system

| Attack | Attack | Remediation | Severity |
| -------- | -------- | -------- | ----- |
| Spoofed |  | OS responsibility |
| Tampered  | Files storing the secrets are modified. Secrets can be lost.  | Check integrity of snapshot with a checksum. Keep older snapshot to be able to restore to a correct state | High |
| Repudiated |              | OS responsibility |
| Information Disclosure | Snapshot content is read | Snapshot content is encrypted | High |
| Denial of Service | Host file system is unavailable. Stronghold cannot commit its current state or load a previous state | Stronghold can continue but can't commit | Mid |
| Elevation of Privileges | Attacker has elevated privilege on the host machine, can read/write/delete snapshots on the file system | Same case as Tampered and Info Disclosure attacks | High |


### Level 3: Memory

| Attack | Attack | Remediation | Severity |
| -------- | -------- | -------- | ----- |
| Spoofed  | | OS responsibility |
| Tampered  | Host system got his memory corrupted. Procedures will produce wrong output, original data can be lost | Secrets are backed by permanent storage called Snapshot. User may use a previous snapshot to restore a previous state | High |
| Repudiated | | OS responsibility |
| Information Disclosure | Secrets are revealed through memory read directly | Secrets are stored encrypted in the memory and decrypted during the least amount of time. Moreover we use Boojum scheme to protect encryption keys in memory. | High |
| Denial of Service | Memory is not accessible preventing Stronghold from working | OS responsibility | Mid |
| Elevation of Privileges |Attacker has elevated privilege on the host machine, can access the secrets in Stronghold | Same case as Tampered and Info Disclosure attacks | High |

### Level 4: Side-channels

| Attack | Attack | Remediation | Severity |
| -------- | -------- | -------- | ----- |
| Spoofed | No potential attack |  |
| Tampered  | Tamper memory using side-channels | Refer to memory and storage table | High |
| Repudiated | No potential attack            |     |
| Information Disclosure | Secrets are revealed through side-channels | Make sure the procedure are constant in time and energy usage (WIP). This also depends on the cryptographic implementation used | High |
| Denial of Service | Prevent normal behaviour of stronghold through side-channels such as electromagnetic waves | Can't protect from software, host responsibility | Mid |
| ~~Elevation of Privileges~~ | No potential attack | |

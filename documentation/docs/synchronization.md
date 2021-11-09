---
description: Synchronization of stored snapshots enables the Stronghold system to become portable
image: /img/logo/Stronghold_icon.png
keywords:
- synchronization
- portability
---
# Synchronization

Synchronization inside Stronghold makes it possible to port snapshots to other running instances, locally or remote

## Types of Synchronization

We distinct between local synchronization, where the target snapshots will be retrievable locally, and remote synchronization where we provide a protocol for secure secrets exchange. Both will be explained in more detail, and examples are given where apropriate. 

## Local Synchronization

Local synchronization enables you to synchronize your local state of your running Stronghold instance, and a provided snapshot you have access to. Local synchronization is split into two modes of operation. The first mode lets you fully synchronize with the other serialized state, the other mode lets you select what `ClientId`s you want to synchronize with your state. The Stronghold interface offers two methods to synchronize with an externally provided snapshot.


```lang: rust

#[actix::main]
async fn main() {

    // TODO show basic usage of local synchronization
}

```

## Remote Synchronization

Synchronizing vault entries with validated remote peers is a bit more complex and is described in the synchronization protocol. We assume two peers namely Alice (A) and Bob (B). B wants to synchronize his entries with A. In order to do that B needs to internally export all of his entries, calculate a shape for each entry that includes its location, size, and some cryptographically sound hash value and send the shapes to A. B must also send a key for A to encrypt exported values for B. 
A does the same steps internally and calculates a complement set from it's own values and the values sent by B. The complement set will then be encrypted by A with the key provided by B, and send to B as a stream of bytes. 


Sequence Diagram:

![Sequence Diagram](https://www.plantuml.com/plantuml/png/dP2nRiCm34JtVCMD3P3-G8SYyTwF86Iw4YgB0acZJR--X8KW6J9rldl7EvxDINrRws72wpicl85_kgY3QWKtry9srnBLj5LoXcNgZ4KKJ2dlpYjUhFpo2LKIUP5sGYRBnu5V0ZTkyo0DiZoI50AtfDVkFEEB8mipBwLnG6bJHbTnIL9nF5n6tjEgG_jtrITuahLNNWE3iG_7j8_HGZLI7Xot6lWkdc-38ZuMxHl71uhVF_h1-icmHjso-E1Yh-xdd9mFvq2sjVu1)
( [_source_][1] )


```lang:rust

#[actix::main]
async fn main() {
    // TODO show basic usage of remote synchronization

}

```

[1]: https://www.plantuml.com/plantuml/png/dP2nRiCm34JtVCMD3P3-G8SYyTwF86Iw4YgB0acZJR--X8KW6J9rldl7EvxDINrRws72wpicl85_kgY3QWKtry9srnBLj5LoXcNgZ4KKJ2dlpYjUhFpo2LKIUP5sGYRBnu5V0ZTkyo0DiZoI50AtfDVkFEEB8mipBwLnG6bJHbTnIL9nF5n6tjEgG_jtrITuahLNNWE3iG_7j8_HGZLI7Xot6lWkdc-38ZuMxHl71uhVF_h1-icmHjso-E1Yh-xdd9mFvq2sjVu1


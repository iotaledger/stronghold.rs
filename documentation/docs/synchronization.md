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

### Local Synchronization

Local synchronization enables you to synchronize your local state of your running Stronghold instance, and a provided snapshot you have access to. Local synchronization is split into two modes of operation. The first mode lets you fully synchronize with the other serialized state, the other mode lets you select what `ClientId`s you want to synchronize with your state. The Stronghold interface offers two methods to synchronize with an externally provided snapshot.


### Remote Synchronization

Synchronizing vault entries with validated remote peers is a bit more complex and is described in the synchronization protocol. We assume two peers namely Alice (A) and Bob (B). B wants to synchronize his entries with A. In order to do that B needs to internally export all of his entries, calculate a shape for each entry that includes its location, size, and some cryptographically sound hash value and send the shapes to A. B must also send a key for A to encrypt exported values for B. 
A does the same steps internally and calculates a complement set from it's own values and the values sent by B. The complement set will then be encrypted by A with the key provided by B, and send to B as a stream of bytes. 

## Problem Domain

We describe two major contexts where synchronization may be used and where a different approach is needed. The two major contexts where synchronization can happen are local and remote. Each context has identical variants in types of synchronization.

### Local¹ 
1. full synchronization per client_id
2. partial synchronization per client_id

(_full synchronization without client_id would be just importing a snapshot / restoring state from local snapshot_)

### Remote² 

1. full synchronization per client_id
2. partial synchronization per client_id
3. full synchronization without client_id ( import )


> **_Notes_**
> 
> ¹ local  synchronization is always related to a snapshot file
> ² remote synchronization is always related to an interaction between two parties > A and B


## Use Cases

We describe use cases where synchronization between two parties A and B might take place.

**_Note_**: Synchronization always involves two parties. Out of tradition the two parties are named Alice (A) and Bob (B).


### Full Import 
Initialize a secondary instance of Stronghold with all entries without having a client_id, and that is only remotely accessible. A real world example would be, that you want to import all wallets from the desktop firefly app into the mobile app.

![https://www.plantuml.com/plantuml/uml/RP0zRiCm38LtdUAD_K4ku268qw5hRn08CWiJaIM3P13azcKgM6tHB1hqFKeVtq4jYbsM74RizZWEU2T3p1bKJ9WKhpZJBHo_wOcBaPG1RpEbCrQIXLMvbgUNvn2pOGJhVRfUQGhe0-tfVnIxTayboMqrQ8chpjLmPPllt-9JweAnPVSO1oYLgUS2uDODv1f_m2R_Ew2KAHbIPeSddluo1nSH9uZ9gWJAIirteiAk-s2NphhTHozaGwuR3dvumry0](https://www.plantuml.com/plantuml/png/RP0zRiCm38LtdUAD_K4ku268qw5hRn08CWiJaIM3P13azcKgM6tHB1hqFKeVtq4jYbsM74RizZWEU2T3p1bKJ9WKhpZJBHo_wOcBaPG1RpEbCrQIXLMvbgUNvn2pOGJhVRfUQGhe0-tfVnIxTayboMqrQ8chpjLmPPllt-9JweAnPVSO1oYLgUS2uDODv1f_m2R_Ew2KAHbIPeSddluo1nSH9uZ9gWJAIirteiAk-s2NphhTHozaGwuR3dvumry0)

### Manual Partial Update
Update a secondary instance of Stronghold with only parts of the entries regarding to the client_id ( context ). Manually selected set. 

![https://www.plantuml.com/plantuml/uml/TP6nJZCn48HxFyMM_m-wF42AA1U4g90G59IHiOUS5MTjUJUAZgV7oU4B0j6uc1bzEzvTYzgYnqCqVRVQBEa1Ic0j0KBlgP2B0QpRuCsc-jkSOd3Zaku6k3rbb4CG2Od_tVmtnaQbdeAGZJ6Tu4tBdya_dEwYtRDB7cTr7dfQb8KkhdF92ibWCqZ7Z7EBVaalOFz7pRxxIaIuwrSqqHj8HdP3IHm-uAV_JYIvX755tj8UOolv3B0hOrOIjbc6fDzRDAqDVaJPWIvhuTqC35mRk6Cfu8fHgsZvrn8KapIbPg1154nhy-1GA_zUQ7CsrAseqfxcYpG7xCswFlN4dm00](https://www.plantuml.com/plantuml/png/TP6nJZCn48HxFyMM_m-wF42AA1U4g90G59IHiOUS5MTjUJUAZgV7oU4B0j6uc1bzEzvTYzgYnqCqVRVQBEa1Ic0j0KBlgP2B0QpRuCsc-jkSOd3Zaku6k3rbb4CG2Od_tVmtnaQbdeAGZJ6Tu4tBdya_dEwYtRDB7cTr7dfQb8KkhdF92ibWCqZ7Z7EBVaalOFz7pRxxIaIuwrSqqHj8HdP3IHm-uAV_JYIvX755tj8UOolv3B0hOrOIjbc6fDzRDAqDVaJPWIvhuTqC35mRk6Cfu8fHgsZvrn8KapIbPg1154nhy-1GA_zUQ7CsrAseqfxcYpG7xCswFlN4dm00)

### Complementary Partial Update
Partially synchronize entries with the remote complement set regarding to the client_id

![https://www.plantuml.com/plantuml/uml/dP2zQWCn48HxFSMK-U7k0QumFfkKWK2Ab4Re5f-mJXBQFSozVMGBoGHtQLJCVgkTcJsBJh8kJerTjni7V7WJ9e9s3kGbMM9S-zHB3-DiLavsWcRmh2D1jaXvSNSOy4r-QXllkD062LamQOi2zZho74GfTSZuAGPdpJRWE9Ev859QBBCD_kNjLMad667vvY5SQL8Llz_vE-cozW_FTV6edLcT5e89ItIqP5Yd3KpI_Yu9dW5eRh7AkSUrMyYnTDAOMl0dfJFXdjUVcr_h9S2iAMK1B5geyZ_92XMfK8ykoJ6LGYRozgcfDgX-lbhFLSy6rJu_w-9-0G00](https://www.plantuml.com/plantuml/png/dP2zQWCn48HxFSMK-U7k0QumFfkKWK2Ab4Re5f-mJXBQFSozVMGBoGHtQLJCVgkTcJsBJh8kJerTjni7V7WJ9e9s3kGbMM9S-zHB3-DiLavsWcRmh2D1jaXvSNSOy4r-QXllkD062LamQOi2zZho74GfTSZuAGPdpJRWE9Ev859QBBCD_kNjLMad667vvY5SQL8Llz_vE-cozW_FTV6edLcT5e89ItIqP5Yd3KpI_Yu9dW5eRh7AkSUrMyYnTDAOMl0dfJFXdjUVcr_h9S2iAMK1B5geyZ_92XMfK8ykoJ6LGYRozgcfDgX-lbhFLSy6rJu_w-9-0G00)

### Remarks

Each use case explicitly **requires a permission check** for remote peers to access records. This permission check is replaced by providing a key to a secondary snapshot file. 
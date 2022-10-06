# STM 

This crate contains two different implementations to have a concurrency in Stronghold.
We have implemented two approaches:

* [Transactional Locking 2 (TL2)](#software-transactional-memory-stm-with-tl2).
* [Read-Log-Update (RLU)](#read-log-update) 


## Overview

### Motivation

Stronghold employs actix as actor framework to manage concurrent operations inside the underlying system. While an actor system is not a bad choice, as it abstracts away difficult synchronization mechanisms, actix explicitly takes ownership of the underlying executor framework, which in turn makes it hard to integrate Stronghold in a shared context. Furthermore actix runs on a single threaded event loop, that renders actor isolation per thread obsolete.

### Software Transactional Memory (STM) with TL2

~In an STM-based system, where all objects with a mutable state are transactional, the behavior of the objects is transparent using the underlying system. This isolates guarded memory, keeping it from being exposed at runtime. Transactions are always safe; internal conflicts are rolled back automatically and retried until the transaction succeeds. Operations on mutable memory are composable. Since only write operations can change the object, these operations must be communicated to the other threads.

Recent work describes multiple approaches, where we consider blocking or retrying other transactions. This is the most viable approach to ensure data consistency. The resulting work is committed to the actual object if the transaction is finished while having all read operations validated; other threads operating on the same object never see the changes done to this object.

The STM described here uses a lazy approach in rolling back a transaction. An STM can also be described as an optimistic locking approach: work on memory is considered safe until a conflict occurs, and the transaction can be safely rolled back and retried.~

We chose to implement the TL2 implementation of STM. You can find the implementation details in the [Transactional Locking II (2006) paper](https://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.90.811&rank=4&q=various%20cross%20version%20operation&osm=&ossid=).
The improvements and tests that have been applied to TL2 are presented in [Testing patterns for software transactional memory engines paper](https://www.researchgate.net/publication/220854689_Testing_patterns_for_software_transactional_memory_engines).

#### Current flaws 

- Variables that can be cloned and shared between threads are classified into the enum `SharedValue.`
  - This is not optimal since we need to import types of Stronghold into this crate to use our STM implementation.
  - We tried to do a generic implementation using trait object (shared types need to implement a trait to be used in STM)
    but we were not successful. This was mostly because the shared variable needed to implement `Clone: Sized` for STM
    , but since they are trait objects, they also need to implement `!Sized`. Implementing both is incompatible.
- This is slow. Tests on Stronghold show most of the time going single-threaded was faster than multi-threaded (x10).

### Read-Log-Update

RLU is an approach similar to STM, with the main difference being that transactions are never rolled back but blocked until they can be committed, producing a consistent state.
You can find Implementation details of RLU in the [Read-Log-Update paper](https://sigops.org/s/conferences/sosp/2015/current/2015-Monterey/printable/077-matveev.pdf).

#### Current flaws 

- Data races and deadlocks occur in the tests.

### Features

[x] - Multiple concurrent reads and writes.
[x] - Lock free integration.
[x] - (optional) Protected memory handling integrated.

# Open Issues / Todo

- Feature-gated secured memory.
- RLU is a global context and must be accessible as mutable from many threads, as new contexts can be spawned anytime.
- Check if `try_lock` needs to return a full copy for the log or if the change has to be delayed.

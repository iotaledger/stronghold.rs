# STM 

This crate contains different implementation to have a concurrency in Stronghold.
Two approaches are implemented: Read-Log-Update (RLU) and Transactional Locking 2 (TL2).


## Overview

### Motivation

Stronghold employs actix as actor framework to manage concurrent operations inside the underlying system. While an actor system is not a bad choice, as it abstracts away difficult synchronization mechanisms, actix explicitly takes ownership of the underlying executor framework, which in turn makes it hard to integrate Stronghold in a shared context. Furthermore actix runs on a single threaded event loop, that renders actor isolation per thread obsolete.

### Software Transactional Memory (STM) with TL2

~In an STM based system all objects having mutable state are transactional, the behavior on the objects are transparently using the underlying system.
This allows to isolate guarded memory from being exposed at runtime.
Transactions are always safe; internal conflicts are rolled back automatically and retried until the transaction succeeds.
Operations on mutable memory are composable.
Since only write operations actually change the object, this operation must be communicated to the other threads.
Recent work describes multiple approaches, where we consider blocking / retrying other transaction the most viable approach to ensure data consistency.
If the transaction has been finished, while having all read operations validated, the resulting work is committed to the actual object.
Other threads operating on the same object, never see the changes done to this object.
The STM described here, uses a lazy approach in rolling back a transaction An STM can also be described as an optimistic locking approach: Work on memory is considered safe until a conflict occurs, the transaction can be safely rolled back and retried.~

We chose to implement the TL2 implementation of STM which implementation details can be found in [[1]](https://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.90.811&rank=4&q=various%20cross%20version%20operation&osm=&ossid=).
Improvements and tests that have been applied to TL2 are presented in [[2]](https://www.researchgate.net/publication/220854689_Testing_patterns_for_software_transactional_memory_engines).

#### Current flaws 
- Variables that can cloned and shared between thread are classified into the enum `SharedValue` 
  - this is a bit ugly since we need to import types of Stronghold into this crate to use our STM implementation
  - we tried to do a generic implementation using trait object (shared types needs to implement a trait to be used in STM)
    but we were not successful. This was mostly due to the fact that shared variable needed to implement `Clone: Sized` for STM
    but since they are trait objects they also need to implement `!Sized`. Implementation of both is incompatible.
- This is slow, tests on Stronghold show most of the time going single-treaded was faster than multi-threaded (x10)

### Read-Log-Update

RLU is an approach similar to STM with the main difference that transactions are never rolled back but blocked until they can be committed to produce a consistent state.
Implementation details of RLU can be found in [[1]](https://sigops.org/s/conferences/sosp/2015/current/2015-Monterey/printable/077-matveev.pdf).

#### Current flaws 
- Data race and deadlocks occur in the tests

### Features

[x] - multiple concurrent reads and writes
[x] - lock free integration
[x] - (optional) protected memory handling integrated

# Open Issues / Todo

- Feature gated secured memory 
- RLU is global context and must be accessible as mutable from many threads, as new contexts can be spawned any time
- check if try_lock needs to return a full copy for the log, or if the change has to be delayed

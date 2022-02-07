# Stronghold Asynchronous Software Transactional Memory

This crate provides an implementation of a commit-time locking software transaction memory (STM). The implementation makes use of `BoxedMemory` for all relevant memory allocations where sensitive data is involved. The amount of time sensitive data is exposed in plain memory is therefore reduced to a minimum, making the STM an ideal framework to work in concurrent setups.

## Overview

### Removal of Actix as actor system

Stronghold employs actix as actor framework to manage concurrent operations inside the underlying system. While an actor system is not a bad choice, as it abstracts away difficult synchronization mechanisms, actix explicitly takes ownership of the underlying executor framework, which in turn makes it hard to integrate Stronghold in a shared context. Furthermore actix runs on a single threaded event loop, that renders actor isolation per thread obsolete.

### Advantages over actor systems

In an STM based system all objects having mutable state are transactional, the behavior on the objects are transparently using the underlying system. This allows to isolate guarded memory from being exposed at runtime. Transactions are always safe; internal conflicts are rolled back automatically and retried until the transaction succeeds. Operations on mutable memory are composable.
Since only write operations actually change the object, this operation must be communicated to the other threads. Recent work describes multiple approaches, where we consider blocking / retrying other transaction the most viable approach to ensure data consistency. if the transaction has been finished, while having all read operations validated, the resulting work is committed to the actual object. Other threads operating on the same object, never see the changes done to this object. The STM described here, uses a lazy approach in rolling back a transaction An STM can also be described as an optimistic locking approach: Work on memory is considered safe until a conflict occurs, the transaction can be safely rolled back and retried.


## Integration

[prose comes here]

### Overview

[prose comes here]

### Features

[prose comes here]

# Open Issues / Todo

- No nested transactions yet ( not explicit lock in values )
- No explicit separation of memory clearing
- Feature gated secured memory 
